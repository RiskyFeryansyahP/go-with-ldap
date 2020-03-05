package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	ldap "github.com/go-ldap/ldap/v3"
)

const view = `<html>
    <head>
        <title>Template</title>
    </head>
    <body>
        <form method="post" action="/login">
            <div>
                <label>username</label>
                <input type="text" name="username" required/>
            </div>
            <div>
                <label>password</label>
                <input type="password" name="password" required/>
            </div>
            <button type="submit">Login</button>
        </form>
    </body>
</html>`

const (
	ldapServer   = "ldap.forumsys.com"
	ldapPort     = 389
	ldapBindDN   = "cn=read-only-admin,dc=example,dc=com"
	ldapPassword = "password"
	ldapSearchDN = "dc=example,dc=com"
)

func loginPage(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("login-template").Parse(view))
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	// otentikasi menggunakan ldap
	ok, data, err := AuthUsingLDAP(username, password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if !ok {
		http.Error(w, "invalid username/password", http.StatusUnauthorized)
		return
	}

	// tampilkan user
	messageFullName := fmt.Sprintf("Selamat Datang %s \n", data.FullName)
	messageEmail := fmt.Sprintf("Email: %s", data.Email)

	w.Write([]byte(messageFullName))
	w.Write([]byte(messageEmail))
}

// AuthUsingLDAP is Method Provide Authentication
func AuthUsingLDAP(username string, password string) (bool, *UserLDAPData, error) {
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort))
	if err != nil {
		log.Println("Gagal Konek LDAP")
		return false, nil, err
	}
	defer l.Close()

	err = l.Bind(ldapBindDN, ldapPassword)
	if err != nil {
		log.Println("Gagal Konek LDAP 2")
		return false, nil, err
	}

	searchRequest := ldap.NewSearchRequest(
		ldapSearchDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)(uid=%s))", username),
		[]string{"dn", "cn", "sn", "mail"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return false, nil, err
	}

	entry := sr.Entries[0]

	err = l.Bind(entry.DN, password)
	if err != nil {
		return false, nil, err
	}

	data := new(UserLDAPData)
	data.ID = username

	for _, attr := range entry.Attributes {
		switch attr.Name {
		case "sn":
			data.Name = attr.Values[0]
		case "mail":
			data.Email = attr.Values[0]
		case "cn":
			data.FullName = attr.Values[0]
		}
	}

	return true, data, nil
}

// UserLDAPData type of User Data
type UserLDAPData struct {
	ID       string
	Name     string
	Email    string
	FullName string
}

func main() {
	http.HandleFunc("/", loginPage)
	http.HandleFunc("/login", login)

	fmt.Println("Server started at localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
