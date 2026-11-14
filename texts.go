package main

import "strings"

// Every finding carries plain-language text in English and Azerbaijani, written for a
// non-technical manager: what it means, and what to do about it.

type Text struct {
	Title string `json:"title"`
	Plain string `json:"plain"`
	Fix   string `json:"fix"`
}

func tx(title, plain, fix string) Text { return Text{title, plain, fix} }

func pair(en, az Text) map[string]Text { return map[string]Text{"en": en, "az": az} }

func rep(x Text, kv ...string) Text {
	r := strings.NewReplacer(kv...)
	return Text{r.Replace(x.Title), r.Replace(x.Plain), r.Replace(x.Fix)}
}

func repPair(p map[string]Text, kv ...string) map[string]Text {
	out := map[string]Text{}
	for k, v := range p {
		out[k] = rep(v, kv...)
	}
	return out
}

// ---- exposed network services -------------------------------------------------

type portDef struct {
	Port int
	Name string
	Kind string
	Sev  Sev
}

var riskyPorts = []portDef{
	{21, "FTP", "fileshare", SevMedium},
	{23, "Telnet", "remote", SevHigh},
	{139, "NetBIOS", "fileshare", SevHigh},
	{445, "SMB file sharing", "fileshare", SevHigh},
	{3389, "Remote Desktop (RDP)", "remote", SevHigh},
	{5900, "VNC remote screen", "remote", SevHigh},
	{1433, "Microsoft SQL Server", "database", SevHigh},
	{3306, "MySQL", "database", SevHigh},
	{5432, "PostgreSQL", "database", SevHigh},
	{1521, "Oracle Database", "database", SevHigh},
	{27017, "MongoDB", "database", SevCritical},
	{6379, "Redis", "database", SevCritical},
	{9200, "Elasticsearch", "database", SevCritical},
	{11211, "Memcached", "database", SevHigh},
	{5984, "CouchDB", "database", SevHigh},
	{2375, "Docker API", "admin", SevCritical},
	{10250, "Kubernetes kubelet", "admin", SevHigh},
	{104, "DICOM imaging", "medical", SevHigh},
	{11112, "DICOM imaging", "medical", SevHigh},
	{2575, "HL7 messaging", "medical", SevHigh},
	{8042, "Orthanc DICOM web", "medical", SevHigh},
}

var infoPorts = []int{22, 80, 443, 8080, 8443}

var portTexts = map[string]map[string]Text{
	"remote": pair(
		tx("{name} is open to the internet (port {port})",
			"Anyone on the internet can reach your remote-access service. Attackers run automated password guessing against these around the clock, and ransomware groups use exposed remote access as their favourite way in.",
			"Close this port on the firewall and reach the server through a VPN instead. Turn on multi-factor authentication."),
		tx("{name} internetə açıqdır (port {port})",
			"İnternetdəki hər kəs uzaqdan idarəetmə xidmətinizə çata bilir. Hücumçular belə xidmətlərə gecə-gündüz avtomatik parol sınaqları edir; fidyəçi proqram qrupları üçün ən sevimli giriş yolu məhz budur.",
			"Portu firewall-da bağlayın, serverə VPN vasitəsilə qoşulun və çoxfaktorlu autentifikasiyanı (MFA) aktiv edin."),
	),
	"database": pair(
		tx("{name} database is reachable from the internet (port {port})",
			"Your database accepts connections from the whole internet. If it is misconfigured or uses a weak or default password, all stored data can be stolen or wiped.",
			"Allow this port only from your application server's IP address (firewall rule) and make sure authentication is switched on."),
		tx("{name} verilənlər bazası internetdən əlçatandır (port {port})",
			"Verilənlər bazanız bütün internetdən qoşulma qəbul edir. Yanlış konfiqurasiya və ya zəif/standart parol olarsa, bütün məlumatlar oğurlana və ya silinə bilər.",
			"Portu yalnız tətbiq serverinin IP ünvanı üçün açıq saxlayın (firewall qaydası) və autentifikasiyanın aktiv olduğunu yoxlayın."),
	),
	"fileshare": pair(
		tx("{name} is open to the internet (port {port})",
			"File-sharing services are a classic entry point for worms and ransomware; the WannaCry outbreak spread through exactly this kind of service.",
			"Block the port at the firewall. Share files over a VPN or a managed cloud drive instead."),
		tx("{name} internetə açıqdır (port {port})",
			"Fayl paylaşma xidmətləri qurd və fidyəçi proqramlar üçün klassik giriş nöqtəsidir; WannaCry epidemiyası məhz belə xidmət vasitəsilə yayılmışdı.",
			"Portu firewall-da bağlayın. Faylları VPN və ya idarə olunan bulud yaddaşı ilə paylaşın."),
	),
	"admin": pair(
		tx("{name} management interface is exposed (port {port})",
			"This management interface can hand complete control of the server to anyone who can reach it, usually without a password.",
			"Close it immediately. Bind it to localhost only, or protect it with TLS client certificates behind a VPN."),
		tx("{name} idarəetmə interfeysi açıqdır (port {port})",
			"Bu idarəetmə interfeysi ona çata bilən hər kəsə, adətən parolsuz, serverə tam nəzarət verə bilər.",
			"Dərhal bağlayın. Yalnız localhost-a bağlayın və ya VPN arxasında TLS client sertifikatı ilə qoruyun."),
	),
	"medical": pair(
		tx("{name} service is reachable from the internet (port {port})",
			"A medical imaging or health-messaging service (DICOM / HL7) can be reached from the internet. These systems often have no login at all and can expose patient records and scans.",
			"Remove it from the public internet. Allow only your hospital or partner IP addresses or a VPN, and enable authentication and encryption."),
		tx("{name} xidməti internetdən əlçatandır (port {port})",
			"Tibbi görüntüləmə və ya sağlamlıq mesajlaşma xidməti (DICOM / HL7) internetdən əlçatandır. Bu sistemlərdə çox vaxt heç giriş parolu olmur və xəstə qeydləri ilə görüntüləri açıq qala bilər.",
			"Xidməti açıq internetdən çıxarın. Yalnız xəstəxana və ya tərəfdaş IP-lərinə yaxud VPN-ə icazə verin, autentifikasiya və şifrələməni aktiv edin."),
	),
}

// ---- exposed files ------------------------------------------------------------

var exposureTexts = map[string]map[string]Text{
	"secrets": pair(
		tx("Secret or configuration file can be downloaded: {path}",
			"Anyone can download this file from your website. Such files usually hold passwords, API keys or database credentials that attackers use to take over your systems.",
			"Remove the file from the public web folder now, treat every password and key inside as stolen and change it, and block dot-files in the web server configuration."),
		tx("Gizli və ya konfiqurasiya faylı yüklənə bilir: {path}",
			"Bu faylı veb saytınızdan istənilən şəxs yükləyə bilər. Belə fayllarda adətən parollar, API açarları və ya verilənlər bazası məlumatları olur; hücumçular bunlarla sistemlərinizi ələ keçirir.",
			"Faylı dərhal ictimai qovluqdan silin, içindəki bütün parol və açarları oğurlanmış sayıb dəyişdirin, veb server konfiqurasiyasında nöqtə ilə başlayan faylları bloklayın."),
	),
	"backup": pair(
		tx("Backup or database dump can be downloaded: {path}",
			"A full copy of your site or database can be downloaded by anyone, including customer or patient data.",
			"Delete it from the web folder, keep backups outside the public directory (or in encrypted storage) and change any passwords stored in it."),
		tx("Ehtiyat nüsxə və ya baza dump-ı yüklənə bilir: {path}",
			"Saytınızın və ya bazanızın tam surətini hər kəs yükləyə bilər; buraya müştəri və ya xəstə məlumatları da daxildir.",
			"Faylı veb qovluğundan silin, ehtiyat nüsxələri ictimai qovluqdan kənarda (və ya şifrələnmiş yaddaşda) saxlayın, içindəki parolları dəyişin."),
	),
	"vcs": pair(
		tx("Source-code repository is exposed: {path}",
			"The .git folder lets attackers rebuild your site's source code, including old passwords and hidden endpoints.",
			"Block access to .git in the web server, deploy builds without the .git folder, and rotate every secret that was ever committed."),
		tx("Mənbə kod anbarı açıqdır: {path}",
			".git qovluğu hücumçulara saytınızın mənbə kodunu, köhnə parolları və gizli ünvanları bərpa etməyə imkan verir.",
			"Veb serverdə .git qovluğuna girişi bloklayın, .git olmadan deploy edin və anbara düşmüş bütün gizli məlumatları dəyişin."),
	),
	"info": pair(
		tx("Diagnostic page is public: {path}",
			"Debug and status pages reveal software versions, settings and sometimes secrets, which makes attacks much easier.",
			"Disable the page or restrict it to internal IPs or authenticated administrators."),
		tx("Diaqnostika səhifəsi hamıya açıqdır: {path}",
			"Debug və status səhifələri proqram versiyalarını, ayarları və bəzən gizli məlumatları göstərir; bu da hücumu xeyli asanlaşdırır.",
			"Səhifəni söndürün və ya yalnız daxili IP-lər və autentifikasiyalı adminlər üçün açıq saxlayın."),
	),
	"admin": pair(
		tx("Admin or database tool is reachable from the internet: {path}",
			"Admin tools are the target of automated login attacks; a single weak password can give full control.",
			"Restrict it to your office or VPN addresses, add multi-factor authentication, or remove it if it is not needed."),
		tx("Admin və ya baza aləti internetdən əlçatandır: {path}",
			"Admin alətləri avtomatik giriş hücumlarının hədəfidir; tək bir zəif parol tam nəzarət verə bilər.",
			"Yalnız ofis və ya VPN ünvanlarına icazə verin, MFA əlavə edin və ya lazım deyilsə silin."),
	),
	"docs": pair(
		tx("API documentation is public: {path}",
			"Public API documentation shows attackers every endpoint to probe. It is only acceptable if each endpoint is properly protected.",
			"Restrict the docs to developers or the VPN, or confirm that every endpoint requires authentication."),
		tx("API sənədləşməsi hamıya açıqdır: {path}",
			"Açıq API sənədləri hücumçulara yoxlanacaq hər ünvanı göstərir. Yalnız hər ünvan düzgün qorunursa məqbuldur.",
			"Sənədləri developerlər və ya VPN üçün məhdudlaşdırın, yaxud hər ünvanın autentifikasiya tələb etdiyini yoxlayın."),
	),
	"misc": pair(
		tx("Hidden system file is exposed: {path}",
			"It leaks folder and file names that should not be public.",
			"Delete it and block access to it."),
		tx("Gizli sistem faylı açıqdır: {path}",
			"İctimai olmamalı qovluq və fayl adlarını sızdırır.",
			"Silin və ona girişi bloklayın."),
	),
}

// ---- TLS ----------------------------------------------------------------------

var (
	txtTLSExpired = pair(
		tx("TLS certificate has expired",
			"Browsers show a scary warning to visitors and some refuse to connect; it also makes it easier for attackers to impersonate your site.",
			"Renew the certificate (free with Let's Encrypt) and enable automatic renewal."),
		tx("TLS sertifikatının müddəti bitib",
			"Brauzerlər ziyarətçilərə qorxuducu xəbərdarlıq göstərir, bəziləri qoşulmaqdan imtina edir; həmçinin hücumçuların saytınızı təqlid etməsini asanlaşdırır.",
			"Sertifikatı yeniləyin (Let's Encrypt ilə pulsuz) və avtomatik yenilənməni aktiv edin."),
	)
	txtTLSExpiring = pair(
		tx("TLS certificate expires in {n} days",
			"If it lapses, visitors get security warnings and your site is effectively offline.",
			"Renew now and set up automatic renewal."),
		tx("TLS sertifikatının bitməsinə {n} gün qalıb",
			"Müddət bitərsə, ziyarətçilər təhlükəsizlik xəbərdarlığı görəcək və sayt faktiki olaraq əlçatmaz olacaq.",
			"İndi yeniləyin və avtomatik yenilənməni qurun."),
	)
	txtTLSUntrusted = pair(
		tx("TLS certificate is not trusted",
			"Browsers cannot verify who runs this site (self-signed certificate or incomplete chain), so visitors see warnings and cannot be sure they reached the real site.",
			"Install a certificate from a trusted authority (for example Let's Encrypt) including the intermediate chain."),
		tx("TLS sertifikatına etibar edilmir",
			"Brauzerlər saytı kimin idarə etdiyini yoxlaya bilmir (özü-imzalı sertifikat və ya natamam zəncir); ziyarətçilər xəbərdarlıq görür və həqiqi sayta qoşulduqlarına əmin ola bilmir.",
			"Etibarlı mərkəzdən (məsələn Let's Encrypt) aralıq zəncirlə birgə sertifikat quraşdırın."),
	)
	txtTLSHostname = pair(
		tx("TLS certificate does not match the site name",
			"The certificate was issued for a different name, so browsers show an error and the connection cannot be trusted.",
			"Issue a certificate that includes this exact domain name."),
		tx("TLS sertifikatı sayt adına uyğun gəlmir",
			"Sertifikat başqa ad üçün verilib; brauzerlər xəta göstərir və əlaqəyə etibar etmək olmur.",
			"Məhz bu domen adını əhatə edən sertifikat buraxın."),
	)
	txtTLSLegacy = pair(
		tx("Outdated TLS versions are enabled (TLS 1.0/1.1)",
			"Old protocol versions have known weaknesses and fail modern compliance requirements.",
			"Allow only TLS 1.2 and TLS 1.3 on the web server or load balancer."),
		tx("Köhnəlmiş TLS versiyaları aktivdir (TLS 1.0/1.1)",
			"Köhnə protokol versiyalarının məlum zəiflikləri var və müasir uyğunluq tələblərinə cavab vermir.",
			"Veb serverdə və ya yük balanslaşdırıcıda yalnız TLS 1.2 və TLS 1.3-ə icazə verin."),
	)
)

// ---- web ----------------------------------------------------------------------

var (
	txtNoHTTPS = pair(
		tx("Website is served without encryption (HTTP only)",
			"Everything visitors type, including passwords and personal data, travels as clear text and can be read or altered on the way.",
			"Install a TLS certificate (free with Let's Encrypt) and redirect all HTTP traffic to HTTPS."),
		tx("Veb sayt şifrələmədən (yalnız HTTP) işləyir",
			"Ziyarətçilərin yazdığı hər şey, o cümlədən parollar və şəxsi məlumatlar, açıq mətn kimi ötürülür və yolda oxuna və ya dəyişdirilə bilər.",
			"TLS sertifikatı quraşdırın (Let's Encrypt ilə pulsuz) və bütün HTTP trafikini HTTPS-ə yönləndirin."),
	)
	txtNoRedirect = pair(
		tx("HTTP does not redirect to HTTPS",
			"Visitors who type the address without https:// stay on the unencrypted version of the site.",
			"Add a permanent (301) redirect from HTTP to HTTPS."),
		tx("HTTP HTTPS-ə yönləndirilmir",
			"Ünvanı https:// olmadan yazan ziyarətçilər saytın şifrələnməmiş versiyasında qalır.",
			"HTTP-dən HTTPS-ə daimi (301) yönləndirmə əlavə edin."),
	)
	txtHSTS = pair(
		tx("HSTS header is missing",
			"Without HSTS, browsers can be tricked into using the unencrypted version of your site, which allows eavesdropping on public Wi-Fi.",
			"Add the header Strict-Transport-Security: max-age=31536000; includeSubDomains."),
		tx("HSTS başlığı yoxdur",
			"HSTS olmadıqda brauzerlər saytın şifrələnməmiş versiyasına yönləndirilə bilər; bu, ictimai Wi-Fi-da dinləməyə imkan verir.",
			"Strict-Transport-Security: max-age=31536000; includeSubDomains başlığını əlavə edin."),
	)
	txtCSP = pair(
		tx("Content-Security-Policy header is missing",
			"A CSP limits which scripts may run on your pages, which reduces the damage if malicious code is injected (XSS).",
			"Add a Content-Security-Policy header; start with default-src 'self' and loosen it only where needed."),
		tx("Content-Security-Policy başlığı yoxdur",
			"CSP səhifələrinizdə hansı skriptlərin işləyə biləcəyini məhdudlaşdırır və zərərli kod yeridilərsə (XSS) ziyanı azaldır.",
			"Content-Security-Policy başlığı əlavə edin; default-src 'self' ilə başlayın və yalnız lazım olan yerdə genişləndirin."),
	)
	txtXFO = pair(
		tx("Clickjacking protection is missing",
			"Another website can embed yours invisibly and trick your users into clicking buttons.",
			"Add X-Frame-Options: DENY or a CSP frame-ancestors 'none' directive."),
		tx("Clickjacking-ə qarşı qoruma yoxdur",
			"Başqa sayt sizinkini gizli şəkildə daxil edib istifadəçilərinizi düymələrə basmağa aldada bilər.",
			"X-Frame-Options: DENY və ya CSP frame-ancestors 'none' direktivi əlavə edin."),
	)
	txtNosniff = pair(
		tx("X-Content-Type-Options header is missing",
			"Browsers may guess file types and run uploaded files as code.",
			"Add X-Content-Type-Options: nosniff."),
		tx("X-Content-Type-Options başlığı yoxdur",
			"Brauzerlər fayl tipini təxmin edib yüklənmiş faylları kod kimi icra edə bilər.",
			"X-Content-Type-Options: nosniff əlavə edin."),
	)
	txtServerVer = pair(
		tx("Server discloses its software version",
			"Version numbers help attackers pick the right exploit for your exact software.",
			"Hide version information (for example ServerTokens Prod, server_tokens off, expose_php = Off)."),
		tx("Server proqram versiyasını açıqlayır",
			"Versiya nömrələri hücumçulara sizin proqrama uyğun exploit seçməkdə kömək edir.",
			"Versiya məlumatını gizlədin (məsələn ServerTokens Prod, server_tokens off, expose_php = Off)."),
	)
	txtCookie = pair(
		tx("Cookie '{name}' lacks security flags",
			"Without the Secure and HttpOnly flags, session cookies can be sniffed on the network or stolen by injected scripts.",
			"Set Secure; HttpOnly; SameSite=Lax on session cookies."),
		tx("'{name}' cookie-sində təhlükəsizlik bayraqları yoxdur",
			"Secure və HttpOnly bayraqları olmadan sessiya cookie-ləri şəbəkədə dinlənə və ya yeridilmiş skriptlər tərəfindən oğurlana bilər.",
			"Sessiya cookie-lərinə Secure; HttpOnly; SameSite=Lax təyin edin."),
	)
)

// ---- e-mail -------------------------------------------------------------------

var (
	txtSPFMissing = pair(
		tx("No SPF record: your domain is easy to spoof by e-mail",
			"Anyone can send e-mails that look like they come from your domain, for example fake invoices to your customers.",
			"Publish an SPF TXT record such as v=spf1 include:<your mail provider> -all."),
		tx("SPF qeydi yoxdur: domeninizlə saxta e-poçt göndərmək asandır",
			"İstənilən şəxs domeninizdən gəlirmiş kimi görünən məktublar, məsələn müştərilərinizə saxta qaimələr göndərə bilər.",
			"SPF TXT qeydi dərc edin, məsələn v=spf1 include:<poçt provayderiniz> -all."),
	)
	txtSPFWeak = pair(
		tx("SPF record is too permissive",
			"An SPF record ending in +all or ?all lets any server send mail as your domain.",
			"End the record with -all (or at least ~all)."),
		tx("SPF qeydi həddindən artıq yumşaqdır",
			"+all və ya ?all ilə bitən SPF qeydi istənilən serverə domeniniz adından məktub göndərməyə icazə verir.",
			"Qeydi -all (ən azı ~all) ilə bitirin."),
	)
	txtDMARCMissing = pair(
		tx("No DMARC policy",
			"Without DMARC, receiving mail servers do not know what to do with forged e-mails from your domain, and you get no reports about abuse.",
			"Publish a _dmarc TXT record such as v=DMARC1; p=quarantine; rua=mailto:you@yourdomain."),
		tx("DMARC siyasəti yoxdur",
			"DMARC olmadan alıcı poçt serverləri domeninizdən gələn saxta məktublarla nə edəcəklərini bilmir və sui-istifadə haqqında hesabat almırsınız.",
			"_dmarc TXT qeydi dərc edin, məsələn v=DMARC1; p=quarantine; rua=mailto:siz@domeniniz."),
	)
	txtDMARCNone = pair(
		tx("DMARC policy is monitor-only (p=none)",
			"Forged e-mails are still delivered; the policy only collects reports.",
			"After reviewing the reports, move to p=quarantine and then p=reject."),
		tx("DMARC siyasəti yalnız monitorinqdir (p=none)",
			"Saxta məktublar yenə də çatdırılır; siyasət yalnız hesabat toplayır.",
			"Hesabatları yoxladıqdan sonra p=quarantine, sonra p=reject-ə keçin."),
	)
)
