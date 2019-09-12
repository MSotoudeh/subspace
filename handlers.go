package main

import (
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jasonlvhit/gocron"
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
	domain := httpHost

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
		i.Domain = domain
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

wg set wg0 peer ${wg_public_key} persistent-keepalive 25 allowed-ips 10.99.97.{{$.Profile.Number}}/32,192.168.1.0/24,192.168.2.0/24,192.168.3.0/24

mkdir peers/{{$.Profile.Name}}
cat <<WGPEER >peers/{{$.Profile.Name}}/{{$.Profile.ID}}.conf
[Peer]
#{{$.Profile.Name}}
PublicKey = ${wg_public_key}
AllowedIPs = 10.99.97.{{$.Profile.Number}}/32,192.168.1.0/24,192.168.2.0/24,192.168.3.0/24
PersistentKeepalive = 25
WGPEER

mkdir clients/{{$.Profile.Name}}
cat <<WGCLIENT >clients/{{$.Profile.Name}}/{{$.Profile.ID}}.conf
[Interface]
PrivateKey = ${wg_private_key}
Address = 10.99.97.{{$.Profile.Number}}/24
[Peer]
#{{$.Profile.Name}}
PublicKey = $(cat server/server.public)
Endpoint = {{$.Domain}}:1234
AllowedIPs = 10.99.97.0/24,192.168.1.0/24,192.168.2.0/24,192.168.3.0/24
PersistentKeepalive = 25
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

func RoundUp(input float64, places int) (newVal float64) {
	var round float64
	pow := math.Pow(10, float64(places))
	digit := pow * input
	round = math.Ceil(digit)
	newVal = round / pow
	return
}

func ByteFormat(inputNum float64, precision int) string {

	if precision <= 0 {
		precision = 1
	}

	var unit string
	var returnVal float64

	if inputNum >= 1000000000000 {
		returnVal = RoundUp((inputNum / 1099511627776), precision)
		unit = " TiB" // terrabyte
	} else if inputNum >= 1000000000 {
		returnVal = RoundUp((inputNum / 1073741824), precision)
		unit = " GiB" // gigabyte
	} else if inputNum >= 1000000 {
		returnVal = RoundUp((inputNum / 1048576), precision)
		unit = " MiB" // megabyte
	} else if inputNum >= 1000 {
		returnVal = RoundUp((inputNum / 1024), precision)
		unit = " KiB" // kilobyte
	} else {
		returnVal = inputNum
		unit = " B" // byte
	}

	return strconv.FormatFloat(returnVal, 'f', precision, 64) + unit
}

func TimeDiff(a, b time.Time) (year, month, day, hour, min, sec int) {
	if a.Location() != b.Location() {
		b = b.In(a.Location())
	}
	if a.After(b) {
		a, b = b, a
	}
	y1, M1, d1 := a.Date()
	y2, M2, d2 := b.Date()

	h1, m1, s1 := a.Clock()
	h2, m2, s2 := b.Clock()

	year = int(y2 - y1)
	month = int(M2 - M1)
	day = int(d2 - d1)
	hour = int(h2 - h1)
	min = int(m2 - m1)
	sec = int(s2 - s1)

	// Normalize negative values
	if sec < 0 {
		sec += 60
		min--
	}
	if min < 0 {
		min += 60
		hour--
	}
	if hour < 0 {
		hour += 24
		day--
	}
	if day < 0 {
		// days in month:
		t := time.Date(y1, M1, 32, 0, 0, 0, 0, time.UTC)
		day += 32 - t.Day()
		month--
	}
	if month < 0 {
		month += 12
		year--
	}

	return
}

func statusHandler(w *Web) {
	wg_dump, err := exec.Command("wg", "show", "all", "dump").Output()
	if err != nil {
		fmt.Printf("error is %s\n", err)
	}
	wg_dump_str := string(wg_dump)
	split_line := strings.Split(wg_dump_str, "\n")

	var split_tab []string
	var AllowedIP_split []string
	var ok bool
	var Datas []Data
	var HandshakeStatus string
	domain := config.Info.Domain

	for i := 0; i < (len(split_line) - 1); i++ {

		split_tab = strings.Split(split_line[i], "\t")
		if len(split_tab) < 9 && ok != true {

			for j := 0; j < 1; j++ {
				if ok != true {
					Datas = []Data{
						Data{
							Type:        "Server",
							Name:        split_tab[0],
							Domain:      domain,
							Private_Key: split_tab[1],
							Public_Key:  split_tab[2],
							Port:        split_tab[3],
						},
					}
				}
				ok = true
			}
		}
		if len(split_tab) == 9 {
			rx, _ := strconv.ParseFloat(strings.TrimSpace(split_tab[6]), 64)
			tx, _ := strconv.ParseFloat(strings.TrimSpace(split_tab[7]), 64)
			Latest_handshake_int, err := strconv.ParseInt(split_tab[5], 10, 64)
			if err != nil {
				panic(err)
			}
			Latest_handshake_Time := time.Unix(Latest_handshake_int, 0)
			year, month, day, hour, min, sec := TimeDiff(Latest_handshake_Time, time.Now())

			if year == 0 && month != 0 {
				HandshakeStatus = fmt.Sprintf("%d months, %d days, %d hours, %d mins and %d seconds ago\n",
					month, day, hour, min, sec)
			} else if year == 0 && month == 0 && day != 0 {
				HandshakeStatus = fmt.Sprintf("%d days, %d hours, %d mins and %d seconds ago\n",
					day, hour, min, sec)
			} else if year == 0 && month == 0 && day == 0 && hour != 0 {
				HandshakeStatus = fmt.Sprintf("%d hours, %d mins and %d seconds ago\n",
					hour, min, sec)
			} else if year == 0 && month == 0 && day == 0 && hour == 0 && min != 0 {
				HandshakeStatus = fmt.Sprintf("%d mins and %d seconds ago\n",
					min, sec)
			} else if year == 0 && month == 0 && day == 0 && hour == 0 && min == 0 && sec != 0 {
				HandshakeStatus = fmt.Sprintf("%d seconds ago\n",
					sec)
			} else {
				HandshakeStatus = fmt.Sprintf("No handshake yet\n")
			}

			AllowedIP_split = strings.Split(split_tab[4], ",")
			// fmt.Println(AllowedIlP_split)
			// for ip := 0; ip < (len(AllowedIP_split)); ip++ {
			// 	fmt.Printf(AllowedIP_split[ip])
			// }

			Dataz :=
				Data{
					Type:             "Peer",
					Name:             split_tab[0],
					Public_Key:       split_tab[1],
					Preshared_Key:    split_tab[2],
					ClientEndpoint:   split_tab[3],
					Allowed:          split_tab[4],
					AllowedIPs:       AllowedIP_split,
					Latest_handshake: HandshakeStatus,
					Transfer_rx:      ByteFormat(rx, 2),
					Transfer_tx:      ByteFormat(tx, 2),
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

func InstalldyndnsServiceHandler(w *Web) {

	gocron.Every(6).Hours().Do(UpdatedyndnsServiceHandler)
	gocron.Start()

	fmt.Printf("\nWill update every 6 hours\n")

	w.Redirect("/dyndns?success=install_dyndns")
}

func UpdatedyndnsServiceHandler() {

	Domain := config.Info.DynDNS.Domain
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
	CurIPTrim := strings.TrimSuffix(CurIP, "\n")

	f, err := os.OpenFile("/tmp/dyndns.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	wrt := io.MultiWriter(os.Stdout, f)
	log.SetOutput(wrt)

	update, err := exec.Command("curl", "https://www.duckdns.org/update?domains="+Domain+"&token="+Token+"&ip=").Output()
	if err != nil {
		//fmt.Printf("\nCMD KO")
		log.Printf("CMD KO")
	}

	update_str := string(update)

	if update_str == "KO" {
		//fmt.Printf("\nKO, could not update DynDNS Domain: " + Domain)
		log.Printf("KO, could not update DynDNS Domain: " + Domain)
	}

	if update_str == "OK" {
		//fmt.Printf("\nOK, updated DynDNS Domain " + Domain + " from " + CurIPTrim + " to " + DynIP)
		log.Printf("OK, updated DynDNS Domain " + Domain + " from " + CurIPTrim + " to " + DynIP)
	}

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
		fmt.Printf("KO")
	}

	if update_str == "OK" {
		w.Redirect("/dyndns?success=update_dyndns")
		fmt.Printf("OK")
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

func serversettingsHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	ip_address := w.r.FormValue("ip_address")
	port := w.r.FormValue("port")
	network_adapter := w.r.FormValue("network_adapter")
	virtual_ip_address := w.r.FormValue("virtual_ip_address")
	cidr := w.r.FormValue("cidr")
	dns := w.r.FormValue("dns")
	public_key := w.r.FormValue("public_key")
	config_path := w.r.FormValue("config_path")

	int_port, err := strconv.Atoi(port)
	if err != nil {
		fmt.Println(err)
	}

	if ip_address != "" || port != "" || network_adapter != "" || virtual_ip_address != "" || cidr != "" || dns != "" || public_key != "" || config_path != "" {
		if err != nil {
			w.Redirect("/serversettings?error=emptywrongtype")
			return
		}
	}

	config.UpdateInfo(func(i *Info) error {
		i.Server.IP_Address = ip_address
		i.Server.Port = int_port
		i.Server.Network_Adapter = network_adapter
		i.Server.Virtual_IP_Address = virtual_ip_address
		i.Server.CIDR = cidr
		i.Server.DNS = dns
		i.Server.Public_Key = public_key
		i.Server.Config_Path = config_path
		return nil
	})

	w.Redirect("/?success=serversettings")
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
