package mail

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"camlistore.org/pkg/blob"
	"camlistore.org/pkg/importer"
	"camlistore.org/pkg/schema/nodeattr"

	"camlistore.org/third_party/github.com/mxk/go-imap/imap"
)

const (
	HostAddr    = "imap.gmail.com:993"
	RequiresSSL = true
)

type run struct {
	*importer.RunContext

	ms     *mailStorer
	client *imap.Client
}

func (r *run) importFromMailbox(mailbox *imap.MailboxInfo) error {
	// store mails in a dynamic directory for the mailbox
	mname := fmt.Sprintf("mailbox/%x", sha1.Sum([]byte(mailbox.Name)))[:16]
	mbNode, err := r.AccountNode().ChildPathObject(mname)
	if err != nil {
		return err
	}
	if err := mbNode.SetAttr("title", mailbox.Name); err != nil {
		return err
	}

	cmd, err := r.client.Select(mailbox.Name, true)
	if err != nil {
		return err
	}

	// ss, err := imap.NewSeqSet("0:*")
	ss, err := imap.NewSeqSet("1:250")
	if err != nil {
		return err
	}

	cmd, err = imap.Wait(r.client.Fetch(ss, "BODY[]", "UID"))
	if err != nil {
		return err
	}

	for i, res := range cmd.Data {
		// in general this works just fine but the theoretical possibility of having
		// attachments greater than memory would make a streaming reader preferable.
		b := imap.AsBytes(res.MessageInfo().Attrs["BODY[]"])
		ref, err := r.ms.Store(mbNode, bytes.NewBuffer(b))
		if err != nil {
			fmt.Println("error:", ref.String())
			ioutil.WriteFile("err.in", b, 0644)
			fmt.Println("Email importer: error importing mail:", err)
			continue
		}

		mby, err := ReadMail(r.Host.BlobSource(), ref)
		if err != nil {
			fmt.Println("Email importer: error reading mail:", err)
			continue
		}
		if !bytes.Equal(b, mby) {
			fmt.Println("mismatch:", ref.String())
			fmt.Println("in len:", len(b), "out len:", len(mby))
			ioutil.WriteFile(ref.String()+".in", b, 0644)
			ioutil.WriteFile(ref.String()+".out", mby, 0644)
		}
		if i%10 == 0 {
			fmt.Println("mails added:", i)
		}

	}

	return nil
}

func (r *run) importMails() error {
	// request list of all mailboxes
	cmd, err := imap.Wait(r.client.List("", "*"))
	if err != nil {
		return err
	}
	for _, res := range cmd.Data {
		log.Println("Email importer: importing from mailbox", res.MailboxInfo().Name)
		if err := r.importFromMailbox(res.MailboxInfo()); err != nil {
			fmt.Println("Email importer: error importing from mailbox:", err)
		}
	}
	return nil
}

type imp struct{}

func init() {
	importer.Register("mail", &imp{})
}

func (im *imp) SupportsIncremental() bool { return false }
func (im *imp) NeedsAPIKey() bool         { return true }

func (im *imp) IsAccountReady(acctNode *importer.Object) (bool, error) {
	// TODO is this enough?
	return acctNode.Attr(importer.AcctAttrUserID) != "", nil
}

func (im *imp) SummarizeAccount(acct *importer.Object) string {
	if ok, err := im.IsAccountReady(acct); !ok {
		s := "Not configured"
		if err != nil {
			s = fmt.Sprintf("%s, error = %s", s, err)
		}
		return s
	}
	return acct.Attr(importer.AcctAttrName)
}

func connect(addr string, reqSSL bool) (*imap.Client, error) {
	if reqSSL {
		// TODO load proper certificates
		tc := &tls.Config{InsecureSkipVerify: true}
		return imap.DialTLS(addr, tc)
	}
	return imap.Dial(addr)
}

func (im *imp) Run(ctx *importer.RunContext) error {

	// imap.DefaultLogger = log.New(os.Stdout, "", 0)
	// imap.DefaultLogMask = imap.LogConn | imap.LogRaw

	c, err := connect(HostAddr, RequiresSSL)
	if err != nil {
		fmt.Println("Connecting to IMAP server failed:", err)
		return err
	}
	defer func() {
		_, err := c.Logout(time.Duration(10) * time.Second)
		if err != nil {
			fmt.Println("Logout failed:", err)
			return
		}
	}()

	// "fab.reinartz", "dgkgsuiptrzlmtjo"
	if _, err := c.Login(
		ctx.AccountNode().Attr(importer.AcctAttrUserID),
		ctx.AccountNode().Attr(importer.AcctAttrAccessToken),
	); err != nil {
		fmt.Println("Login failed:", err)
		return fmt.Errorf("Login failed: %s", err)
	}

	r := &run{ctx, &mailStorer{ctx.Host.Target(), ctx.Host.BlobSource()}, c}
	if err := r.importMails(); err != nil {
		return err
	}
	return nil
}

func (im *imp) ServeSetup(w http.ResponseWriter, r *http.Request, ctx *importer.SetupContext) error {
	uid, secret, err := ctx.Credentials()
	if err != nil {
		return err
	}

	if err := ctx.AccountNode.SetAttrs(
		importer.AcctAttrUserID, uid,
		importer.AcctAttrUserName, uid,
		importer.AcctAttrAccessToken, secret,
		nodeattr.Title, fmt.Sprintf("%s's emails", uid),
	); err != nil {
		return err
	}
	http.Redirect(w, r, ctx.AccountURL(), http.StatusFound)
	return nil
}

// Noops as the importer is not based on OAuth
func (im *imp) ServeCallback(w http.ResponseWriter, r *http.Request, ctx *importer.SetupContext) {}
func (im *imp) CallbackRequestAccount(r *http.Request) (acctRef blob.Ref, err error) {
	return blob.Ref{}, nil
}
func (im *imp) CallbackURLParameters(acctRef blob.Ref) url.Values { return nil }

var _ importer.ImporterSetupHTMLer = (*imp)(nil)

func (im *imp) AccountSetupHTML(host *importer.Host) string {
	return fmt.Sprintf(`<h1>Configuring Email importer</h1><p>Enter your access details above</p>`)
}
