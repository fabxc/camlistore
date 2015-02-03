package mail

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/mail"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"camlistore.org/pkg/blob"
	"camlistore.org/pkg/blobserver"
	"camlistore.org/pkg/importer"
	"camlistore.org/pkg/schema"
)

var (
	crlf = []byte("\r\n")
	lf   = []byte("\n")
)

// ReadMail restores the original email stored in the mail schema
// blob ref points to.
func ReadMail(bf blob.Fetcher, ref blob.Ref) ([]byte, error) {
	r, _, err := bf.Fetch(ref)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	mb, err := schema.BlobFromReader(ref, r)
	if err != nil {
		return nil, err
	}
	parts := mb.ByteParts()

	var totalSize uint64
	for _, p := range parts {
		totalSize += p.Size
	}
	mailBuf := bytes.NewBuffer(make([]byte, 0, totalSize))

	writeBytes := func(bl *schema.Blob) error {
		fr, err := bl.NewFileReader(bf)
		if err != nil {
			return err
		}
		defer fr.Close()

		var encInfo struct {
			Encoding       string `json:"mimeEncoding"`
			LineLength     string `json:"lineLength"`
			LinebreakBytes string `json:"linebreakBytes"`
		}
		err = json.Unmarshal([]byte(bl.JSON()), &encInfo)
		if err != nil {
			return err
		}

		var w io.Writer
		if encInfo.Encoding == "base64" {
			ll, err := strconv.Atoi(encInfo.LineLength)
			if err != nil {
				return err
			}
			bw := base64.NewEncoder(base64.StdEncoding, &linebreakWriter{mailBuf, ll, []byte(encInfo.LinebreakBytes), 0})
			defer bw.Close()
			w = bw
		} else {
			w = mailBuf
		}
		_, err = io.Copy(w, fr)
		return err
	}

	var nullRef blob.Ref
	for _, p := range parts {
		// blobs can be read straight into the buffer
		if p.BlobRef != nullRef {
			br, s, err := bf.Fetch(p.BlobRef)
			if err != nil {
				return nil, err
			}
			_, err = io.CopyN(mailBuf, br, int64(s))
			br.Close()
			if err != nil {
				return nil, err
			}

			// byte schema blobs have to be encoded and padded properly if
			// they were stored decoded
		} else if p.BytesRef != nullRef {
			br, _, err := bf.Fetch(p.BytesRef)
			if err != nil {
				return nil, err
			}
			bl, err := schema.BlobFromReader(p.BytesRef, br)
			if err != nil {
				return nil, err
			}

			err = writeBytes(bl)
			if err != nil {
				return nil, err
			}
		} else {
			panic("invalid part")
		}
	}
	return mailBuf.Bytes(), nil
}

// linebreakWriter relays writes to w while inserting the defined linebreakBytes
// after every lineLength bytes.
type linebreakWriter struct {
	w io.Writer

	lineLength     int
	linebreakBytes []byte
	curLineLength  int
}

func (lw *linebreakWriter) Write(d []byte) (n int, err error) {
	fmt.Println("write:", string(d))
	var m int
	for len(d) > n+lw.lineLength-lw.curLineLength {
		m, err = lw.w.Write(d[n : n+lw.lineLength-lw.curLineLength])
		n += m
		if err != nil {
			return
		}
		_, err = lw.w.Write(lw.linebreakBytes)
		if err != nil {
			return
		}
		lw.curLineLength = 0
	}
	if len(d) > n {
		m, err = lw.w.Write(d[n:])
		n += m
		if err != nil {
			return
		}
		lw.curLineLength = m
	}
	return
}

// mailStorer stores mails.
type mailStorer struct {
	br blobserver.StatReceiver
	bs blob.Fetcher
}

func newMailStorer(br blobserver.StatReceiver, bs blob.Fetcher) *mailStorer {
	return &mailStorer{
		br: br,
		bs: bs,
	}
}

type storePart struct {
	header []byte
	footer []byte
	parts  []schema.BytesPart
	size   int64
}

func (ms *mailStorer) Store(parent *importer.Object, r io.Reader) (blob.Ref, error) {
	bufReader := bufio.NewReader(r)
	headerBytes, err := readUntilBody(bufReader)
	if err != nil {
		return blob.Ref{}, err
	}

	header, err := readMIMEHeader(headerBytes)
	if err != nil {
		return blob.Ref{}, err
	}
	sp := &storePart{
		header: headerBytes,
		footer: nil,
		// reserve first slot for header
		parts: make([]schema.BytesPart, 1, 16),
		size:  0,
	}

	err = ms.storeBody(sp, header, bufReader)
	if err != nil {
		return blob.Ref{}, err
	}

	// upload mail header blob
	sp.parts[0], err = uploadBlobPart(ms.br, sp.header)
	if err != nil {
		return blob.Ref{}, err
	}
	sp.size += int64(sp.parts[0].Size)
	bp, err := uploadBlobPart(ms.br, sp.footer)
	if err != nil {
		return blob.Ref{}, err
	}
	sp.parts = append(sp.parts, bp)
	sp.size += int64(bp.Size)

	// build mime schema blob
	bb := schema.NewBuilder()

	bb.SetType("mail")
	// TODO fix mismatch int64 vs uint64
	err = bb.PopulateParts(sp.size, sp.parts)
	if err != nil {
		fmt.Println(1, err)
		return blob.Ref{}, err
	}
	mb := bb.Blob()
	_, err = uploadBytes(ms.br, mb.BlobRef(), []byte(mb.JSON()))
	if err != nil {
		return blob.Ref{}, err
	}
	fmt.Println(">>>> stored:", mb.BlobRef())

	date, err := mail.Header(header).Date()
	if err != nil {
		return blob.Ref{}, err
	}
	path := []string{
		strconv.Itoa(date.Year()),
		strconv.Itoa(int(date.Month())),
		strconv.Itoa(int(date.Day())),
	}
	obj, err := getPathObj(parent, path)
	if err != nil {
		return blob.Ref{}, err
	}

	attrs := []string{
		"camliContent", mb.BlobRef().String(),
		"messageId", header.Get("Message-ID"),
		"title", decodeField(header.Get("Subject")),
		"from", decodeField(header.Get("From")),
		"createdAt", date.Format(time.RFC3339),
	}

	addresses, err := mail.ParseAddressList(header.Get("To"))
	if err != nil {
		return blob.Ref{}, err
	}
	for _, a := range addresses {
		attrs = append(attrs, "to", decodeField(a.String()))
	}

	if err := obj.SetAttrs(attrs...); err != nil {
		return blob.Ref{}, err
	}

	return mb.BlobRef(), nil

}

// storeBody stores a multipart body.
func (ms *mailStorer) storeBody(sp *storePart, header textproto.MIMEHeader, r io.Reader) error {
	ct := header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		return ms.storeFile(sp, header, r, params["filename"])
	}

	br := bufio.NewReader(r)
	mr := NewMultipartReader(br, params["boundary"])

	var headerBytes, finalBytes []byte
	first := true
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// Prepend the lines that seperated the current part from the
		// previous ones.
		// LastDelimLine should never be nil for a valid multipart
		sp.header = append(sp.header, mr.LastDelimLine()...)
		sp.header = append(sp.header, p.HeaderBytes()...)

		var i int
		if !first {
			// reserve field for header
			i = len(sp.parts)
			sp.parts = append(sp.parts, schema.BytesPart{})
		}

		err = ms.storeBody(sp, p.Header, p)
		if err != nil {
			return err
		}

		if first {
			headerBytes = sp.header
			first = false
		} else {
			if finalBytes != nil {
				sp.header = append(finalBytes, sp.header...)
			}
			sp.parts[i], err = uploadBlobPart(ms.br, sp.header)
			if err != nil {
				return err
			}
			sp.size += int64(sp.parts[i].Size)
		}
		finalBytes = sp.footer
		sp.footer = nil
		sp.header = nil
	}
	sp.header = headerBytes
	sp.footer = append(finalBytes, mr.LastDelimLine()...)

	return nil
}

// storeContentBody stores a multipart file body
func (ms *mailStorer) storeFile(sp *storePart, header textproto.MIMEHeader, r io.Reader, filename string) error {
	// sr := &trimReader{br: bufio.NewReader(r)}
	sr := r
	var fr io.Reader
	var ls *linebreakSanitizer

	// buf := new(bytes.Buffer)
	if header.Get("Content-Transfer-Encoding") == "base64" {
		fmt.Println("has base64")
		ls = newLinebreakSanitizer()
		fr = base64.NewDecoder(base64.StdEncoding, io.TeeReader(sr, ls))
	} else {
		fr = sr
	}
	// at this point there should be no more \n or \r chars
	// before or after the content unless it is non-multipart
	fref, err := schema.WriteFileFromReader(ms.br, filename, fr)
	if err != nil {
		return err
	}
	fmt.Println("wrote file", fref)

	// create new bytes ref with same blobs as the file object
	// and additional information to restore the contents exactly
	// as in the original email
	bb := schema.NewBuilder()
	bb.SetType("bytes")
	bb.SetRawStringField("file", fref.String())

	if ls != nil {
		// TODO: fallback to storing the file decoded and the raw base64
		// to recover the exact email
		if ls.err != nil {
			return ls.err
		}
		// store information that allows exact recovery
		bb.SetRawStringField("mimeEncoding", "base64")
		bb.SetRawStringField("lineLength", strconv.Itoa(ls.firstLineLen))
		bb.SetRawStringField("linebreakBytes", string(ls.bytes))
	}

	file, _, err := ms.bs.Fetch(fref)
	if err != nil {
		return err
	}
	fileBlob, err := schema.BlobFromReader(fref, file)
	if err != nil {
		return err
	}

	err = bb.PopulateParts(fileBlob.PartsSize(), fileBlob.ByteParts())
	if err != nil {
		return err
	}
	b := bb.Blob()

	// upload mime file parts blob
	_, err = uploadBytes(ms.br, b.BlobRef(), []byte(b.JSON()))
	if err != nil {
		return err
	}
	sp.size += fileBlob.PartsSize()
	sp.parts = append(sp.parts, schema.BytesPart{
		BytesRef: b.BlobRef(),
		Size:     uint64(fileBlob.PartsSize()),
	})
	// add sourrounding \n and \r
	if ls != nil {
		hbts, fbts := ls.TrimmedBytes()
		fmt.Println("trimmed: ", strconv.Quote(string(hbts)), strconv.Quote(string(fbts)))
		sp.header = append(sp.header, hbts...)
		sp.footer = append(fbts, sp.footer...)
	}
	return nil
}

// getPathObj creates a path of child nodes from the given node and returns
// the final node.
func getPathObj(parent *importer.Object, path []string) (*importer.Object, error) {
	var err error
	for _, p := range path {
		parent, err = parent.ChildPathObject(p)
		if err != nil {
			return nil, err
		}
		err = parent.SetAttr("title", p)
		if err != nil {
			return nil, err
		}
	}
	return parent, nil
}

// linebreakSanitizer wraps a io.Reader and checks if its content's
// have a consistent line padding, that is, all except for the last
// line a seperated after the same number of characters and by the
// same linebreak sequence.
type linebreakSanitizer struct {
	// r   io.Reader
	buf *bytes.Buffer

	firstLineLen int
	bytes        []byte

	prev    byte
	lineLen int
	err     error
}

func newLinebreakSanitizer() *linebreakSanitizer {
	return &linebreakSanitizer{
		buf: new(bytes.Buffer),
		firstLineLen: -1,
	}
}

func (ls *linebreakSanitizer) Bytes() []byte {
	return ls.buf.Bytes()
}

func (ls *linebreakSanitizer) TrimmedBytes() ([]byte, []byte) {
	b := ls.Bytes()
	ln := len(bytes.TrimLeft(b, "\r\n\t"))
	rn := len(bytes.TrimRight(b, "\r\n\t"))
	return b[:len(b)-ln], b[rn:]
}

// Read into the given byte slice. If an inconsistency is detected
// the reader remains working and keeps reading from the underlying reader.
func (ls *linebreakSanitizer) Write(d []byte) (n int, err error) {
	// dc := make([]byte, len(d))
	n, err = ls.buf.Write(d)
	if err != nil || ls.err != nil {
		return
	}	
	fmt.Println("read:", string(d))

	for _, c := range d[:n] {
		if c == '\n' {
			if ls.firstLineLen == -1 {
				ls.firstLineLen = ls.lineLen
				if ls.prev == '\r' {
					ls.bytes = crlf
				} else {
					ls.bytes = lf
				}
			} else if ls.firstLineLen != ls.lineLen {
				ls.err = fmt.Errorf("linebreakSanitizer: line length mismatch: expected %d, got %d", ls.firstLineLen, ls.lineLen)
			} else if (ls.prev == '\r') != (bytes.Equal(ls.bytes, crlf)) {
				ls.err = fmt.Errorf("linebreakSanitizer: inconsistent newline bytes")
			}
			ls.lineLen = 0
		} else if c != '\r' {
			ls.lineLen++
		}
		ls.prev = c
	}
	return
}

// trimReader wraps a bufio.Reader and returns its contents trimmed off of any
// sourrounding \r and \n characters
// type trimReader struct {
// 	br             *bufio.Reader
// 	contentStarted bool
// 	pre, post      []byte
// 	endBuf         []byte
// }

// // Read trimed data from the wrapped bufio.Reader.
// func (tr *trimReader) Read(d []byte) (int, error) {
// 	if !tr.contentStarted {
// 		tr.pre = make([]byte, 0, 23)
// 		for {
// 			c, err := tr.br.ReadByte()
// 			if err != nil {
// 				return 0, err
// 			}
// 			if c != '\n' && c != '\r' {
// 				if err := tr.br.UnreadByte(); err != nil {
// 					return 0, err
// 				}
// 				tr.contentStarted = true
// 				break
// 			}
// 			tr.pre = append(tr.pre, c)
// 		}
// 		return tr.Read(d)

// 	} else if tr.endBuf != nil {
// 		n := copy(d, tr.endBuf)
// 		if n < len(tr.endBuf) {
// 			tr.endBuf = tr.endBuf[n:]
// 			return n, nil
// 		}
// 		return n, io.EOF

// 	} else {
// 		i := 0
// 		nn := 0
// 		for {
// 			// we go ahead and assume that there will not be more than 1024 cr or lf
// 			// chars after the actual content and that the buffer size is >= 1024
// 			// TODO: same issue as in mime/multipart due to missing buffer size accessor
// 			pb, err := tr.br.Peek(1024)
// 			if err == io.EOF {
// 				contentEnd := 0
// 				// check for trailing cr and lf
// 				for i := len(pb) - 1; i >= 0; i-- {
// 					c := pb[i]
// 					if c != '\n' && c != '\r' {
// 						contentEnd = i + 1
// 						break
// 					}
// 				}
// 				tr.post = pb[contentEnd:]

// 				to := i*1024 + contentEnd
// 				if len(d) < to {
// 					tr.endBuf = pb[len(d):contentEnd]
// 					to = len(d)
// 				}
// 				n, err := tr.br.Read(d[i*1024 : to])
// 				nn += n
// 				if err != nil {
// 					return nn, err
// 				}
// 				if n < contentEnd {
// 					return nn, nil
// 				}
// 				return nn, io.EOF
// 			}
// 			if err != nil {
// 				return 0, err
// 			}
// 			// read another 1024 byte chunk or less if d is too short
// 			to := (i + 1) * 1024
// 			if len(d) < to {
// 				to = len(d)
// 			}
// 			n, err := tr.br.Read(d[i*1024 : to])
// 			nn += n
// 			if err != nil {
// 				return nn, err
// 			}
// 			if nn == len(d) {
// 				break
// 			}
// 			i++
// 		}
// 		return nn, nil
// 	}
// }

// // TrimmedBytes returns the bytes that pre- and suceeded the readers'
// // contents. It only returns valid slices after the reader has been read up to io.EOF.
// func (tr *trimReader) TrimmedBytes() ([]byte, []byte) {
// 	return tr.pre, tr.post
// }

// read until first double linebreak and return the
// bytes read so far including the linebreaks
func readUntilBody(br *bufio.Reader) ([]byte, error) {
	headerBytes := make([]byte, 0, 4096)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		headerBytes = append(headerBytes, line...)

		if len(line) == 1 || len(line) == 2 && line[0] == '\r' {
			break
		}
	}
	return headerBytes, nil
}

// readMIMEHeader parses the given bytes into a MIMEHeader.
func readMIMEHeader(b []byte) (textproto.MIMEHeader, error) {
	tpr := textproto.NewReader(bufio.NewReader(bytes.NewBuffer(b)))
	return tpr.ReadMIMEHeader()
}

// uploadBlobPart uploads a slice of bytes and returns a respective schema.BytesPart
func uploadBlobPart(bs blobserver.StatReceiver, b []byte) (schema.BytesPart, error) {
	br := blob.SHA1FromBytes(b)
	_, err := uploadBytes(bs, br, b)
	if err != nil {
		return schema.BytesPart{}, err
	}
	return schema.BytesPart{BlobRef: br, Size: uint64(len(b))}, nil
}

// uploadBytes uploads a slice of bytes if it doesn't exist already
func uploadBytes(bs blobserver.StatReceiver, br blob.Ref, b []byte) (blob.Ref, error) {
	if !br.Valid() {
		panic("invalid blobref")
	}
	hasIt, err := serverHasBlob(bs, br)
	if err != nil {
		return blob.Ref{}, err
	}
	if hasIt {
		return br, nil
	}
	_, err = blobserver.ReceiveNoHash(bs, br, bytes.NewReader(b))
	if err != nil {
		return blob.Ref{}, err
	}
	return br, nil
}

// serverHasBlob checks if a blob with the given blobref already exisys
func serverHasBlob(bs blobserver.BlobStatter, br blob.Ref) (have bool, err error) {
	_, err = blobserver.StatBlob(bs, br)
	if err == nil {
		have = true
	} else if err == os.ErrNotExist {
		err = nil
	}
	return
}

// word-encoding decoder taken from the net/mail package
// (which probably should decode regular fields as well and not just addressess)

func isWordEncoded(s string) bool {
	return strings.HasPrefix(s, "=?") && strings.HasSuffix(s, "?=") && strings.Count(s, "?") == 4
}

func decodeField(s string) string {
	ss := strings.Split(s, " ")
	for i, p := range ss {
		if !isWordEncoded(p) {
			continue
		}
		dp, err := decodeRFC2047Word(p)
		if err != nil {
			fmt.Errorf("Unable to decode word: %v", err)
			continue
		}
		ss[i] = dp
	}
	return strings.Join(ss, " ")
}

func decodeRFC2047Word(s string) (string, error) {
	fields := strings.Split(s, "?")
	if len(fields) != 5 || fields[0] != "=" || fields[4] != "=" {
		return "", errors.New("address not RFC 2047 encoded")
	}
	charset, enc := strings.ToLower(fields[1]), strings.ToLower(fields[2])
	if charset != "us-ascii" && charset != "iso-8859-1" && charset != "utf-8" {
		return "", fmt.Errorf("charset not supported: %q", charset)
	}

	in := bytes.NewBufferString(fields[3])
	var r io.Reader
	switch enc {
	case "b":
		r = base64.NewDecoder(base64.StdEncoding, in)
	case "q":
		r = qDecoder{r: in}
	default:
		return "", fmt.Errorf("RFC 2047 encoding not supported: %q", enc)
	}

	dec, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}

	switch charset {
	case "us-ascii":
		b := new(bytes.Buffer)
		for _, c := range dec {
			if c >= 0x80 {
				b.WriteRune(unicode.ReplacementChar)
			} else {
				b.WriteRune(rune(c))
			}
		}
		return b.String(), nil
	case "iso-8859-1":
		b := new(bytes.Buffer)
		for _, c := range dec {
			b.WriteRune(rune(c))
		}
		return b.String(), nil
	case "utf-8":
		return string(dec), nil
	}
	panic("unreachable")
}

type qDecoder struct {
	r       io.Reader
	scratch [2]byte
}

func (qd qDecoder) Read(p []byte) (n int, err error) {
	// This method writes at most one byte into p.
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := qd.r.Read(qd.scratch[:1]); err != nil {
		return 0, err
	}
	switch c := qd.scratch[0]; {
	case c == '=':
		if _, err := io.ReadFull(qd.r, qd.scratch[:2]); err != nil {
			return 0, err
		}
		x, err := strconv.ParseInt(string(qd.scratch[:2]), 16, 64)
		if err != nil {
			return 0, fmt.Errorf("mail: invalid RFC 2047 encoding: %q", qd.scratch[:2])
		}
		p[0] = byte(x)
	case c == '_':
		p[0] = ' '
	default:
		p[0] = c
	}
	return 1, nil
}
