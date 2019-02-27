package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	validEmail    = regexp.MustCompile(`^[ -~]+@[ -~]+$`)
	validPassword = regexp.MustCompile(`^[ -~]{6,200}$`)
	validString   = regexp.MustCompile(`^[ -~]{1,200}$`)
)

func wireguardConfigHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	f, err := os.Open(profile.WireGuardConfigPath())
	if err != nil {
		logger.Warn(err)
		Error(w.w, fmt.Errorf("config file error"))
		return
	}

	stat, err := f.Stat()
	if err != nil {
		logger.Warn(err)
		Error(w.w, fmt.Errorf("config file size error"))
		return
	}

	w.w.Header().Set("Content-Disposition", "attachment; filename="+profile.WireGuardConfigName())
	w.w.Header().Set("Content-Type", "application/x-wireguard-profile")
	w.w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	_, err = io.Copy(w.w, f)
	if err != nil {
		logger.Error(err)
		Error(w.w, fmt.Errorf("config output error"))
		return
	}
}

func wireguardPNGHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	f, err := os.Open(profile.WireGuardPNGPath())
	if err != nil {
		logger.Warn(err)
		Error(w.w, fmt.Errorf("png file error"))
		return
	}

	stat, err := f.Stat()
	if err != nil {
		logger.Warn(err)
		Error(w.w, fmt.Errorf("png file size error"))
		return
	}

	w.w.Header().Set("Content-Disposition", "attachment; filename="+profile.WireGuardPNGName())
	w.w.Header().Set("Content-Type", "application/x-wireguard-profile")
	w.w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	_, err = io.Copy(w.w, f)
	if err != nil {
		logger.Error(err)
		Error(w.w, fmt.Errorf("config output error"))
		return
	}
}

func configureHandler(w *Web) {
	if config.FindInfo().Configured {
		w.Redirect("/?error=configured")
		return
	}

	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	emailConfirm := strings.ToLower(strings.TrimSpace(w.r.FormValue("email_confirm")))
	password := w.r.FormValue("password")

	if !validEmail.MatchString(email) || !validPassword.MatchString(password) || email != emailConfirm {
		w.Redirect("/configure?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}
	config.UpdateInfo(func(i *Info) error {
		i.Email = email
		i.Password = hashedPassword
		i.Configured = true
		return nil
	})

	sessionCookie, err := NewSessionCookie(w.r)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)
	w.Redirect("/")
	return
}

func forgotHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	secret := w.r.FormValue("secret")
	password := w.r.FormValue("password")

	if email != "" && !validEmail.MatchString(email) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if secret != "" && !validString.MatchString(secret) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if email != "" && secret != "" && !validPassword.MatchString(password) {
		w.Redirect("/forgot?error=invalid&email=%s&secret=%s", email, secret)
		return
	}

	if email != config.FindInfo().Email {
		w.Redirect("/forgot?error=invalid")
		return
	}

	if secret == "" {
		secret = config.FindInfo().Secret
		if secret == "" {
			secret = RandomString(32)
			config.UpdateInfo(func(i *Info) error {
				if i.Secret == "" {
					i.Secret = secret
				}
				return nil
			})
		}

		go func() {
			if err := mailer.Forgot(email, secret); err != nil {
				logger.Error(err)
			}
		}()

		w.Redirect("/forgot?success=forgot")
		return
	}

	if secret != config.FindInfo().Secret {
		w.Redirect("/forgot?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}
	config.UpdateInfo(func(i *Info) error {
		i.Password = hashedPassword
		i.Secret = ""
		return nil
	})

	sessionCookie, err := NewSessionCookie(w.r)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)
	w.Redirect("/")
	return
}

func signoutHandler(w *Web) {
	http.SetCookie(w.w, NewDeletionCookie())
	w.Redirect("/signin")
}

func signinHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	password := w.r.FormValue("password")

	if email != config.FindInfo().Email {
		w.Redirect("/signin?error=invalid")
		return
	}

	if err := bcrypt.CompareHashAndPassword(config.FindInfo().Password, []byte(password)); err != nil {
		w.Redirect("/signin?error=invalid")
		return
	}
	sessionCookie, err := NewSessionCookie(w.r)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w.w, sessionCookie)

	w.Redirect("/")
}

func addProfileHandler(w *Web) {
	name := strings.TrimSpace(w.r.FormValue("name"))
	platform := strings.TrimSpace(w.r.FormValue("platform"))

	if platform == "" {
		platform = "other"
	}

	if name == "" {
		w.Redirect("/?error=profilename")
		return
	}

	profile, err := config.AddProfile(name, platform)
	if err != nil {
		logger.Warn(err)
		w.Redirect("/?error=addprofile")
		return
	}

	// /etc/wireguard
	// folder each: server, clients, peers, config
	//
	script := `
cd /etc/wireguard
wg_private_key="$(wg genkey)"
wg_public_key="$(echo $wg_private_key | wg pubkey)"

wg set wg0 peer ${wg_public_key} allowed-ips 10.99.97.{{$.Profile.Number}}/32,192.168.1.0/24,192.168.2.0/24,192.168.3.0/24

mkdir peers/{{$.Profile.Name}}
cat <<WGPEER >peers/{{$.Profile.Name}}/{{$.Profile.ID}}.conf
[Peer]
PublicKey = ${wg_public_key}
AllowedIPs = 10.99.97.{{$.Profile.Number}}/32,192.168.1.0/24,192.168.2.0/24,192.168.3.0/24
WGPEER

mkdir clients/{{$.Profile.Name}}
cat <<WGCLIENT >clients/{{$.Profile.Name}}/{{$.Profile.ID}}.conf
[Interface]
PrivateKey = ${wg_private_key}
Address = 10.99.97.{{$.Profile.Number}}/24
[Peer]
PublicKey = $(cat server/server.public)
Endpoint = {{$.Domain}}:5555
AllowedIPs = 10.99.97.0/24,192.168.1.0/24,192.168.2.0/24,192.168.3.0/24
PersistentKeepalive = 15
WGCLIENT
qrencode -t PNG -o clients/{{$.Profile.Name}}/{{$.Profile.ID}}.png < clients/{{$.Profile.Name}}/{{$.Profile.ID}}.conf
`
	_, err = bash(script, struct {
		Profile Profile
		Domain  string
	}{
		profile,
		httpHost,
	})
	if err != nil {
		logger.Warn(err)
		w.Redirect("/?error=addprofile")
		return
	}

	w.Redirect("/profiles/connect/%s?success=addprofile", profile.ID)
}

func connectProfileHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	w.Profile = profile
	w.HTML()
	return
}

func deleteProfileHandler(w *Web) {
	profileID := w.ps.ByName("profile")
	if profileID == "" {
		profileID = w.r.FormValue("profile")
	}
	profile, err := config.FindProfile(profileID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}

	if w.r.Method == "GET" {
		w.Profile = profile
		w.HTML()
		return
	}

	// /etc/wireguard
	// folder each: server, clients, peers, config
	//
	script := `
cd /etc/wireguard
peerid=$(cat peers/{{$.Profile.Name}}/{{$.Profile.ID}}.conf | perl -ne 'print $1 if /PublicKey\s*=\s*(.*)/')
wg set wg0 peer $peerid remove
rm peers/{{$.Profile.Name}}/{{$.Profile.ID}}.conf
rm clients/{{$.Profile.Name}}/{{$.Profile.ID}}.conf
rm clients/{{$.Profile.Name}}/{{$.Profile.ID}}.png
rm -rf peers/{{$.Profile.Name}}
rm -rf clients/{{$.Profile.Name}}
`
	output, err := bash(script, struct {
		Profile Profile
	}{
		profile,
	})
	if err != nil {
		logger.Warnf("delete profile failed %s %s", err, output)
		w.Redirect("/profiles/delete?error=removeprofile")
		return
	}

	if err := config.DeleteProfile(profile.ID); err != nil {
		panic(err)
	}
	w.Redirect("/?success=removeprofile")
}

func indexHandler(w *Web) {
	profiles := config.ListProfiles()

	w.Profiles = profiles
	w.HTML()
}

func statusHandler(w *Web) {
	wg_dump, err := exec.Command("wg", "show", "all", "dump").Output()
	if err != nil {
		fmt.Printf("error is %s\n", err)
	}
	wg_dump_str := string(wg_dump)
	split_line := strings.Split(wg_dump_str, "\n")

	// profile, err := config.FindProfile(w.ps.ByName("profile"))
	// if err != nil {
	// 	fmt.Printf("error is %s\n", err)
	// 	return
	// }

	var split_tab []string
	var ok bool
	var Datas []Data

	for i := 0; i < (len(split_line) - 1); i++ {
		split_tab = strings.Split(split_line[i], "\t")
		if len(split_tab) < 9 && ok != true {

			for j := 0; j < 1; j++ {
				if ok != true {
					Datas = []Data{
						Data{
							Type:        "Server",
							Name:        split_tab[0],
							Public_Key:  split_tab[1],
							Private_Key: split_tab[2],
							Port:        split_tab[3],
							Keepalive:   split_tab[4],
						},
					}
				}
				ok = true
			}
		}
		if len(split_tab) == 9 {
			Dataz :=
				Data{
					Type:             "Peer",
					Name:             split_tab[0],
					Public_Key:       split_tab[1],
					Allowed:          split_tab[4],
					Latest_handshake: split_tab[5],
					Transfer_rx:      split_tab[6],
					Transfer_tx:      split_tab[7],
					Keepalive:        split_tab[8],
				}
			Datas = append(Datas, Dataz)
		}
	}
	w.Statuses = Datas
	w.HTML()
}

func dyndnsHandler(w *Web) {

	Domain := config.Info.DynDNS.Domain
	//FQDomain := Domain + ".duckdns.org"
	Token := config.Info.DynDNS.Token

	domain_ip_cmd, err := exec.Command("dig", "+short", Domain).Output()
	if err != nil {
		fmt.Printf("error is %s\n", err)
	}

	current_ip_cmd, err := exec.Command("curl", "ifconfig.co").Output()
	if err != nil {
		fmt.Printf("error is %s\n", err)
	}

	domain_ip_str := string(domain_ip_cmd)
	DynIP := domain_ip_str
	current_ip_str := string(current_ip_cmd)
	CurIP := current_ip_str

	w.DynDNS.Domain = Domain
	w.DynDNS.Token = Token
	w.DynDNS.DynIP = DynIP
	w.DynDNS.IP = CurIP

	w.HTML()
}

func UpdatedyndnsHandler(w *Web) {

	Domain := config.Info.DynDNS.Domain
	Token := config.Info.DynDNS.Token

	update, err := exec.Command("curl", "https://www.duckdns.org/update?domains="+Domain+"&token="+Token+"&ip=").Output()
	if err != nil {
		w.Redirect("/dyndns?error=cannotupdate")
	}

	update_str := string(update)

	if update_str == "KO" {
		w.Redirect("/dyndns?error=cannotupdate")
	}

	if update_str == "OK" {
		w.Redirect("/dyndns?success=update_dyndns")
	}

}

func settingsHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	currentPassword := w.r.FormValue("current_password")
	newPassword := w.r.FormValue("new_password")

	if currentPassword != "" || newPassword != "" {
		if !validPassword.MatchString(newPassword) {
			w.Redirect("/settings?error=invalid")
			return
		}

		if err := bcrypt.CompareHashAndPassword(config.FindInfo().Password, []byte(currentPassword)); err != nil {
			w.Redirect("/settings?error=invalid")
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			w.Redirect("/settings?error=bcrypt")
			return
		}

		config.UpdateInfo(func(i *Info) error {
			i.Email = email
			i.Password = hashedPassword
			return nil
		})
	}

	config.UpdateInfo(func(i *Info) error {
		i.Email = email
		return nil
	})

	w.Redirect("/?success=settings")
}

func emailsettingsHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	from := strings.ToLower(strings.TrimSpace(w.r.FormValue("from")))
	server := strings.ToLower(strings.TrimSpace(w.r.FormValue("server")))
	port := w.r.FormValue("port")
	username := strings.ToLower(strings.TrimSpace(w.r.FormValue("username")))
	password := w.r.FormValue("password")

	int_port, err := strconv.Atoi(port)
	if err != nil {
		fmt.Println(err)
	}

	if from != "" || server != "" || port != "" || username != "" || password != "" {
		if err != nil {
			w.Redirect("/emailsettings?error=emptywrongtype")
			return
		}
	}

	config.UpdateInfo(func(i *Info) error {
		i.Mail.From = from
		i.Mail.Server = server
		i.Mail.Port = int_port
		i.Mail.Username = username
		i.Mail.Password = password
		return nil
	})

	w.Redirect("/?success=emailsettings")
}

func dyndnssettingsHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	domain := strings.ToLower(strings.TrimSpace(w.r.FormValue("domain")))
	token := strings.ToLower(strings.TrimSpace(w.r.FormValue("token")))

	if domain == "" || token == "" {
		w.Redirect("/dyndnssettings?error=empty")
	}

	config.UpdateInfo(func(i *Info) error {
		i.DynDNS.Domain = domain
		i.DynDNS.Token = token
		return nil
	})

	w.Redirect("/?success=dyndnssettings")
}

func helpHandler(w *Web) {
	w.HTML()
}
