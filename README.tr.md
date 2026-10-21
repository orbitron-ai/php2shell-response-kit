# php2shell — CVE-2026-109618 / CVE-2026-109619 · ORBITRON müdahale kiti

> **Durum: v1.3.0 — YAMALAR YAYINLANDI (21.10.2026).** PHP **8.5.12, 8.4.27, 8.3.36 ve 8.2.35** sürümlerini yayınladı.
> Script'ler artık düzeltilmiş sürümleri biliyor ve PHP duyurusundaki geçici önlemleri kontrol ediyor; tetikleme
> koşulu için yeni kurallar eklendi. *Açıklama öncesi* bölümler kayıt için korunuyor. Değişiklikler: [CHANGELOG.md](CHANGELOG.md).
>
> English version: [README.md](README.md)

## Özet

* PHP çekirdeğinde kimlik doğrulama gerektirmeyen iki kritik uzaktan kod çalıştırma (RCE) açığı (her biri CVSS v4.0 9.2).
  **PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 ile düzeltildi** (21 Ekim 2026). PHP 8.1 ve öncesi: upstream yama yok.
* **Kök neden (resmi yamadan):** PHP **isteği ayrıştırırken** (POST / multipart / upload verisi — henüz hiçbir
  script çalışmadan) `memory_limit` aşılırsa işlemi yarıda kesiyor ve istek durumunu yarım bırakıyor
  (CVE-2026-109618) ya da bu durum **aynı worker'daki bir sonraki isteğe** taşınıyor (CVE-2026-109619).
  Erişilebilir herhangi bir `.php` dosyası yeterli; en riskli SAPI mod_php, PHP-FPM de etkileniyor.
* **Güncelleyin ve tüm PHP worker'larını yeniden başlatın — tek tam çözüm bu.**
* PHP duyurusundaki geçici önlemler (yalnızca riski azaltır): `memory_limit = -1` **ve cgroup/container bellek
  sınırı**, `post_max_size = 8M` (dosya yükleme varsa 32M), `session.upload_progress.enabled = 0`,
  `fatal_error_backtraces = 0` (8.5). Lab'ımızda PHP'nin kendi regresyon testi isteğinde kesintiyi yalnızca
  `memory_limit = -1` engelledi (§9).
* Bu kit: envanter script'leri (düzeltilmiş sürüm + önlem kontrolü, container'lar dahil) ve Sigma, Splunk,
  QRadar, CrowdStrike Falcon, SentinelOne, Wazuh, YARA ve ModSecurity kuralları — her birinde neyin test
  edildiği belirtilmiş.

## 1. Olay nedir?

| Konu | Durum |
|---|---|
| Düzeltilmiş sürümler 8.5.12, 8.4.27, 8.3.36, 8.2.35 (21 Ekim 2026) | **Doğrulandı** — php.net sürüm duyuruları |
| CVE-2026-109618 = GHSA-w8hw-w9fx-j79w, CVE-2026-109619 = GHSA-6wmf-4rv5-p3rp | **Doğrulandı** — PHP NEWS ve "Avoid state corruption via bailout" düzeltme commit'i |
| Açık sınıfı: istek başlatma / ayrıştırma sırasında bellek tükenmesi kesintisinden sonra durum bozulması; bayat istek durumunun sonraki istekte kullanılması | **Doğrulandı** — php.net duyuru metni ve yama (OOM kesintisi kontrollü çıkışla değiştirildi; global'ler sıfırlanıyor; ayrıştırıcı yumuşak sınırda duruyor) |
| En riskli mod_php; kimlik doğrulamasız, uygulama kodu çalışmadan önce | **Doğrulandı** — php.net |
| Her biri CVSS v4.0 9.2 olan iki kritik PHP açığı | php.net tarafından **doğrulandı** (20 Ekim ön duyurusu) |
| Açık sınıfı: PHP çekirdeğinde kimlik doğrulamasız RCE | watchTowr (CVE-2026-109618'i yeniden üretti) ve diğerleri bildirdi; PHP detay yayınlamadı |
| CVE numaraları CVE-2026-109618 / CVE-2026-109619 | watchTowr ve sızan materyalden; php.net duyurusunda geçmiyor; kayıtlar "reserved" |
| "php2shell" adı ve PHP ≥ 5.4'ü hedeflediğini iddia eden "PHP2Shell" aracı | Ekran görüntüsü sızıntısı — doğrulanmadı |
| Etkilenen sürümler "PHP 5'ten 8'e kadar" | Bildirildi — **doğrulanmadı** |
| Yama yalnızca desteklenen dallar için (8.2, 8.3, 8.4, 8.5) | Bildirildi; PHP destek politikasıyla uyumlu |
| *Session Upload Progress* (`ext/session`) ile bağlantı, bellek bozulması | GMO Flatt Security'nin açıklama öncesi değerlendirmesi. **Yama, bunun nedenin kendisi değil yollardan biri olduğunu gösteriyor**: upload-progress işleyicisi de sıkılaştırıldı (istek başlamadan sınıf çözümleme / kullanıcı kodu yok, geride `$_SESSION` kalmıyor) |
| Sahada aktif istismar | 21 Ekim sabahı itibarıyla bildirilmedi (watchTowr, Huntress) |

Zaman çizelgesi: 20 Ekim ~18:20 TSİ Hacker News'te sızıntı → 20 Ekim 22:33 TSİ PHP ön duyurusu →
21 Ekim: php.net'te düzeltilmiş sürümler ve duyuru.

## 2. Neden önemli?

* PHP, açık web'in büyük bir bölümünü çalıştırıyor: WordPress/WooCommerce, Magento/Adobe Commerce,
  Shopware, Drupal, Laravel/Symfony uygulamaları, hosting panelleri ve PHP gömülü birçok cihaz.
* Yorumlayıcı çekirdeğindeki bir RCE, etkilenen runtime üzerindeki *her* uygulama üzerinden erişilebilir;
  uygulama sıkılaştırması ve uygulama içi WAF eklentileri PHP isteği işledikten *sonra* devreye girer.
* Araştırmacılar (ör. Sansec) yama diff'i açığı ele vereceği için yayından dakikalar sonra kitlesel
  istismar bekliyor.
* Desteği bitmiş (EOL) sürüm nüfusu büyük: internet taramaları PHP 8.1 veya öncesini ilan eden yüz
  binlerce sunucu sayıyor; bunlara upstream yama gelmeyecek.

## 3. Etkilenen sistemler — şu an bilinenler

| Runtime | Durum (21 Ekim) |
|---|---|
| php.net, Remi, deb.sury.org, resmi Docker imajları ve Windows build'lerinden gelen PHP 8.2 / 8.3 / 8.4 / 8.5 | **Upstream'de 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 ile düzeltildi** — yeniden paketlenmiş build'ler arkadan gelir |
| PHP 8.1 ve öncesi (upstream EOL) | **Upstream yama yok.** Yalnızca dağıtım/ESM/üretici backport'u veya yükseltme |
| Dağıtım paketleri (RHEL/Rocky/Alma, Debian, Ubuntu, SUSE) | Yama dağıtımın güvenlik süreciyle gelir — zamanlama farklı, bkz. §7 |
| Tüm SAPI'ler (mod_php, PHP-FPM, CGI/FastCGI, LiteSpeed) | php.net: en riskli mod_php. Kalıcı worker'lar (mod_php, FPM, LiteSpeed) bayat durumu istekler arasında taşır; istek başına açılan CGI süreçleri taşımaz |

## 4. Neleri kontrol etmek lazım? (script'leri kullanın)

| Script | Platform | Ne yapar |
|---|---|---|
| [`scripts/linux/php2shell-check.sh`](scripts/linux/php2shell-check.sh) | Linux (RHEL ailesi, Debian/Ubuntu, Alpine, cPanel/Plesk/CloudLinux/Remi yolları) | Tüm PHP binary'lerini ve SAPI'leri bulur, SAPI bazında **etkin** ayarları okur (CLI, FPM, CGI, mod_php ini seti), FPM pool / web sunucusu / `.user.ini` / `.htaccess` override'larını listeler, paket ve kaynağını (dağıtım, Remi, Sury), paket changelog'unda CVE'lerin geçip geçmediğini, çalışan süreçleri, **çalışan FPM worker'larının / Apache alt süreçlerinin son config değişikliğinden sonra başlatılıp başlatılmadığını ve güncel binary'yi kullanıp kullanmadığını** (`LOADED` / `STALE` / `RESTART REQUIRED`) ve **sunucudaki container / Kubernetes pod'larının içindeki PHP'yi** (Docker, Podman, containerd, CRI-O) `/proc/<pid>/root` üzerinden salt okunur inceleyerek raporlar — container bazında sürüm, paket, `session.upload_progress` ve çalışma durumu; `crictl`/`docker`/`podman` varsa pod/container adlarıyla |
| [`scripts/windows/php2shell-check.ps1`](scripts/windows/php2shell-check.ps1) | Windows (IIS FastCGI, XAMPP, WAMP, Laragon, Plesk, PATH, çalışan süreçler) | Aynısını Windows için yapar; her IIS FastCGI uygulamasını kendi argümanları/`PHPRC` değeriyle değerlendirir; çalışan `php-cgi.exe` / Apache süreçlerinin son `php.ini` değişikliğinden veya PHP binary'sinden eski olup olmadığını kontrol eder (IIS `monitorChangesTo` dahil) |

İkisi de **yalnızca okuma yapar**, ağ bağlantısı kurmaz ve istismar denemez. Filo genelinde toplama
için JSON çıktı verir (ör. ORBITRON Command Engine, Ansible, SCCM/Intune).

```bash
sudo bash php2shell-check.sh                 # okunabilir çıktı
sudo bash php2shell-check.sh -o report.json  # + JSON
sudo bash php2shell-check.sh --no-containers   # (salt okunur) container / pod incelemesini atla
sudo bash php2shell-check.sh --container-exec  # ek olarak docker/podman exec ile 'php -r' çalıştırıp kesin CLI değerlerini al
```
```powershell
powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1 -OutFile report.json
```
Çıkış kodları: `0` PHP yok, `1` PHP var ve tüm runtime'lar yamalı doğrulandı, `2` PHP var ve en az bir
runtime yamalı **doğrulanamadı**.

v1.3.0'dan itibaren düzeltilmiş sürümler **8.2.35 8.3.36 8.4.27 8.5.12** script'lerin içinde
(`PHP2SHELL_FIXED_UPSTREAM` ile değiştirilebilir). Linux script'i, yamayı backport eden dağıtım paketlerine
(RHEL/Ubuntu eski sürüm numarasını korur) upstream sürüm karşılaştırması **uygulamaz**; bunlar için paket
changelog'unda CVE'nin geçmesine bakar. Her runtime için ayrıca bir `Interim:` satırı (JSON'da
`interim_mitigations`) duyurudaki dört ayardan hangilerinin etkin olduğunu gösterir. Override listesi artık
pool / vhost / dizin düzeyindeki `memory_limit` ve `post_max_size` değerlerini de içeriyor; bunlar
php.ini'deki önlemi sessizce geçersiz kılabilir.

Kontrol listesi:
1. Her PHP runtime'ını **ve web sunucusunun gerçekten kullandığı SAPI'yi** envanterleyin (CLI değerleri ≠ FPM değerleri).
2. Dağıtım/ESM backport'u kapsamında olmayan upstream-EOL dalları (≤ 8.1) işaretleyin.
3. Paketlerinizin nereden geldiğini kaydedin (dağıtım, Remi, Sury, panel üreticisi) — ne zaman yama yapabileceğinizi bu belirler.
4. İnternete açık sunuculara öncelik verin; 21 Ekim 17:00 TSİ sonrası için değişiklik pencereleri hazırlayın.
5. Güncellemeden sonra FPM pool'larının / container'ların **yeniden başlatıldığını** kontrol edin (çalışan worker eski binary'yi kullanmaya devam eder).
   Yukarıdaki ayarlar diskteki ini dosyalarından okunur; çalışan süreçlerin bunları gerçekten kullanıp kullanmadığını
   `Running:` satırı gösterir. `STALE` = reload gerekli, `RESTART REQUIRED` = süreçler paket güncellemesiyle değiştirilmiş
   eski binary'yi çalıştırıyor.

## 5. Bilinen workaround'lar — güncel durum

PHP duyurusu aşağıdaki geçici önlemleri listeliyor. **Bunlar riski azaltır, kurulumu güvenli hale getirmez.**
php.ini, FPM pool (`php_admin_value` / `php_admin_flag`) veya web sunucusu yapılandırmasında ayarlayın —
`ini_set()` veya `.user.ini` ile **değil** — ve **tüm PHP worker'larını yeniden başlatın**.

```ini
memory_limit = -1                      ; FPM: php_admin_value[memory_limit] = -1 (uygulama ezemez)
post_max_size = 8M                     ; dosya yükleme gerekiyorsa 32M
session.upload_progress.enabled = 0
fatal_error_backtraces = 0             ; yalnızca PHP 8.5
```

| Workaround | Durum (21 Ekim, yayın sonrası) | Notlar |
|---|---|---|
| `memory_limit = -1` | **Temel geçici önlem** (php.net). Lab'ımızda ayrıştırma sırasındaki bellek kesintisini engelleyen tek ayar (§9) | **DoS riski doğurur**: birkaç MB'lık bir isteğin ayrıştırılması yüzlerce MB bellek harcayabilir. Belleği cgroup/container sınırıyla kısıtlayın (php-fpm/httpd için systemd `MemoryMax=`, container memory limit, IIS app pool private memory limit) ve `pm.max_children`'ı buna göre ayarlayın. php.net: cgroup kullanın, `RLIMIT_AS` / `RLIMIT_DATA` **değil**. |
| `post_max_size = 8M` (yükleme varsa 32M) | Destekleyici (php.net) | 8M zaten PHP varsayılanı. Lab'ımızda **tek başına engellemedi**: 3 MB'lık gövde 128M'yi tüketti. |
| `session.upload_progress.enabled = 0` | Destekleyici (php.net); bir büyütücüyü kaldırır | Lab'ımızda **tek başına engellemedi**. `INI_PERDIR`: php.ini, FPM `php_admin_flag`, Apache `php_admin_flag`. |
| `fatal_error_backtraces = 0` | Yalnızca PHP 8.5 (php.net) | Sonrasında worker'ları yeniden başlatın. |
| `session.use_strict_mode = 1` | **Azaltım değil** (lab notlarımız, §9) | Yine de iyi bir hijyen ayarı. |
| WAF / ModSecurity | **Avlama + gövde sınırları** | Önerilen `SecRequestBodyNoFilesLimit 131072` + `SecRequestBodyLimitAction Reject` ayarı lab'ımızda PHP'nin regresyon testi gövdesini reddetti. 9109622/23 kuralları part-başlık selini ve gövde hatalarını loglar. |
| Web sunucusu izin listesi: PHP'ye yalnızca mevcut ve kullanılan `.php` giriş noktaları ulaşsın; `LimitRequestBody` / `client_max_body_size`; form olmayan yerlerde yalnızca `GET`/`HEAD` | **Etkili, düşük maliyetli** (§9a) | PHP-FPM, var olmayan script'ler için de gövdeyi ayrıştırıyor. Apache: `.php` `FilesMatch` içinde `<If "! -f %{REQUEST_FILENAME}">Require all denied</If>`; nginx: `try_files $uri =404;`. PHP yalnızca bir iletişim formu için varsa, yamalı paket gelene kadar PHP'yi durdurmayı düşünün. |
| Maruziyeti kısıtlama (VPN/IP izin listesi, yönetim panellerini kapatma, EOL sunucuları izole etme) | Etkili risk azaltımı | CERT-EU, yama gelene kadar internete açık uygulamaların izole edilmesini öneriyor. |
| PHP kullanıcısı için en az yetki, çıkış (egress) filtreleme, salt okunur web kökleri | Etkiyi sınırlar | Flatt Security de öneriyor; webshell kalıcılığını da zorlaştırır. |
| Yama | **Çözüm** | Upstream 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; dağıtım zamanlaması §7. Worker'ları yeniden başlatın. |

## 6. Tespit ve izleme kuralları

Ayrıntılı tespit ve müdahale saha rehberi (log örnekleri, SAPI farkları, korelasyon): [docs/php2shell-tespit-ve-mudahale-rehberi.md](docs/php2shell-tespit-ve-mudahale-rehberi.md). Markalı PDF sürümünün doküman-kontrol numarası (v1.2) bu repo rehberine karşılık gelir; repo Markdown'ı daha sonraki küçük düzeltmeleri taşıyabilir. Markalı PDF sürümleri: [EN](docs/ORBITRON_php2shell_EN_v1.2.pdf) · [TR](docs/ORBITRON_php2shell_TR_v1.2.pdf).

Yama artık açık olduğu için burada iki tür kural var: **tetikleme koşulu** kuralları (PHP bir isteği
ayrıştırırken belleği tükendi — açığın ihtiyaç duyduğu durum — ve WAF'ta part-başlık seli) ve saldırganın kod
çalıştırdıktan *sonra* yaptıklarını yakalayan **davranışsal** kurallar.
**Tüm SIEM/EDR sorguları canlı platformlarda TEST EDİLMEDİ** (Sigma kaynaklarından pySigma ile üretildi);
YARA, ModSecurity ve script'ler lab'ımızda test edildi. Alarm açmadan önce 1–2 saat baseline alın.

| Kullanım senaryosu | Sigma (kaynak) | Splunk | QRadar | CrowdStrike Falcon | SentinelOne | Wazuh | Diğer |
|---|---|---|---|---|---|---|---|
| Linux: PHP/web sunucusu shell, yorumlayıcı, indirme/keşif aracı başlatıyor | `lnx_..._spawns_shell_or_lolbin.yml` | `.spl`, `.cim.spl` | `.aql`, `.payload.aql` | `.logscale` | `.dv`, `.pq` | 109610–109612 (auditd) | — |
| Linux: PHP'den reverse shell / keşif komut satırı | `lnx_..._suspicious_cmdline.yml` | ✓ | ✓ | ✓ | ✓ | 109613 | — |
| Windows: php-cgi/php/httpd/w3wp shell/LOLBin başlatıyor | `win_..._spawns_shell_or_lolbin.yml` | ✓ | ✓ | ✓ | ✓ | 109620 (Sysmon) | — |
| Web köküne webshell / `.user.ini` / `.htaccess` yazılması | `lnx_/win_..._file_written_to_webroot.yml` | ✓ | ✓ | Falcon'un yerleşik webshell tespitleri | ✓ | 109615, 109616, 109621 | YARA |
| **PHP isteği ayrıştırırken belleği tükendi** (`Allowed memory size … in Unknown on line 0`) — tetikleme koşulu | `php2shell_php_oom_during_request_parsing.yml` | ✓ | payload | ✓ (log ingestion gerekir) | — | 109627, 109629 (seri) | — |
| **Ayrıştırma sırasında bellek tükenmesinden sonra 2 dk içinde worker çökmesi** | — | — | — | — | — | 109628 (seviye 14) | — |
| **PHP-FPM worker'ı code 70 ile kapandı** (başlatmada OOM — sinyalle çökme değil, temiz çıkış) | `php2shell_php_fpm_worker_exit_code70.yml` | ✓ | payload | ✓ (log ingestion gerekir) | — | 109630, 109631 (OOM ile) | — |
| PHP worker çökmesi (SIGSEGV/SIGABRT) — bellek bozulması denemeleri | `php2shell_php_worker_crash.yml` | ✓ | payload | ✓ (log ingestion gerekir) | — | 109625, 109626 | — |
| Multipart part-başlık seli / istek gövdesi hataları | — | — | — | — | — | — | ModSecurity 9109622, 9109623 |
| Multipart isteklerde upload-progress alanı | — | — | — | — | — | — | ModSecurity 9109618/19/21 (+ engelleme 9109620) |
| Webshell, auto_prepend kalıcılığı, upload-progress session kalıntıları | — | — | — | — | — | — | YARA `rules/yara/` |

Veri gereksinimleri: üst süreç bilgisiyle süreç oluşturma (Linux/Windows için Sysmon, auditd `execve`,
EDR), web kökü kuralları için dosya oluşturma telemetrisi, çökme kuralı için PHP-FPM/Apache hata
logları, ModSecurity için istek gövdesi incelemesi. Bellek tükenmesi kuralı, PHP hatalarının iletilen bir
log'da olmasını gerektirir (`log_errors=On`; FPM için `catch_workers_output=yes` veya pool `error_log`).
Yamalı sunucularda da bu mesaj görülebilir (PHP artık temiz duruyor) — bunu ele geçirilme değil, deneme
göstergesi olarak değerlendirin. Platform notları:

* **Splunk** — `.spl` Sysmon alan adlarını (`Image`, `ParentImage`, `CommandLine`), `.cim.spl` CIM Endpoint veri modelini kullanır.
* **QRadar** — alan tabanlı `.aql` Sysmon/EDR custom property'leri (*Parent Process Path*, *Command*) gerektirir; Linux OS DSM (auditd) genelde üst süreç bilgisi taşımaz → `.payload.aql` veya Wazuh/auditd yaklaşımı.
* **CrowdStrike Falcon** — `ProcessRollup2` üzerinde LogScale / NG-SIEM / Advanced Event Search sözdizimi; dosya yazma kuralları üretilmedi (pipeline kısıtı).
* **SentinelOne** — `.dv` (Deep Visibility) `endswith` mantığını korur; `.pq` backend'i `endswith`'i `contains` ile yaklaşık çevirir (daha geniş eşleşme).
* **Wazuh** — `rules/wazuh/0910-orbitron-php2shell_rules.xml` + `auditd-php2shell.rules` + `ossec-agent-snippet.xml`. `wazuh-logtest` ile doğrulayın.
* **YARA** — `yara -r rules/yara/php2shell_hunting.yar /var/www` ve PHP session dizini.
* Platform sorgularını yeniden üretmek için: `python3 tools/build_rules.py` (bkz. `rules/BUILD_REPORT.md`).

Beklenen false positive'ler: meşru `exec()` kullanan PHP uygulamaları (görsel/PDF araçları, yedekleme,
deploy hook'ları, kontrol panelleri), PHP `mail()` (`sh -c sendmail`, filtrelendi), kendi `.php`
dosyalarını yazan CMS güncellemeleri, çöken üçüncü taraf eklentiler.

## 7. Güncelleme takvimi ve yamanın platformlara ulaşma süreci

| Kaynak | Yama nasıl gelir | Ne beklemeli / nasıl doğrulanır |
|---|---|---|
| **php.net (upstream)** | 21 Ekim 17:00 TSİ'de (veya daha erken) 8.2–8.5 için yeni ara sürümler | Gösterge sürüm numarasıdır (düzeltilmiş sürümler duyuruyla yayınlanır) |
| **Windows** (windows.php.net build'leri, XAMPP/WAMP/Laragon, IIS) | PHP binary'lerini yeni build ile değiştirin; paketlenmiş yığınlar daha sonra gelir | `php -v`; IIS app pool / Apache yeniden başlatma |
| **Remi (RHEL ailesi) / deb.sury.org ve ondrej PPA (Debian/Ubuntu)** | Upstream sürümleri takip eder, genelde yeni upstream sürümleri hızlı yayınlar | Upstream sürüm numarası geçerli; `dnf update` / `apt upgrade`, FPM yeniden başlatma |
| **RHEL 8/9/10 → Rocky / AlmaLinux / Oracle** | Red Hat yamayı mevcut pakete **backport** eder (sürüm numarası değişmez); Rocky/Alma RHSA'yı yeniden derler (Rocky'nin RLSA bildirimleri RHSA'dan aktarılır) | Geçmişte aynı gün gelmedi: ör. Mayıs 2026 PHP yamaları RHEL'e RHSA-2026:22143 (php:8.2, RHEL 9, 20 Temmuz tarihli), Rocky 8'e RLSA-2026:34354 (2 Temmuz) ile ulaştı. Kontrol: `dnf updateinfo list --cve CVE-2026-109618` ve `rpm -q --changelog php-common \| grep CVE-2026-10961` |
| **Debian** | Debian Güvenlik Ekibi DSA yayınlar; PHP için son dönemde yeni upstream ara sürümü gönderdi (ör. DSA-6255-1 → `8.2.31-1~deb12u1`, upstream'den bir gün sonra) | `apt list --upgradable 'php*'`; security-tracker.debian.org |
| **Ubuntu** | **Backport** edilmiş yamalarla USN (ör. `8.3.6-0ubuntu0.24.04.x` korunur); eski sürümler Ubuntu Pro/ESM ile | Geçmiş PHP USN'leri upstream'den günler-haftalar sonra geldi (ör. USN-8564-1, 20 Temmuz). ubuntu.com/security/CVE-… ve changelog'u kontrol edin |
| **Container'lar** (resmi `php:` imajları, özel imajlar) | İmajlar upstream yayından sonra yeniden derlenir | Yeniden derleyin **ve yeniden deploy edin**; sabitlenmiş base imajlar kendiliğinden güncellenmez |
| **Hosting panelleri / CloudLinux / cihazlar** (cPanel EA-PHP, Plesk, alt-php, üreticiler) | Üreticiye özgü | Hosting/panel/cihaz üreticisinden *bugün* hazır beklemesini isteyin |
| **Upstream EOL (≤ 8.1)** | Upstream yama yok | Yükseltme, üretici/ESM backport'u veya izolasyon |

Her durumda: güncellemeden sonra **PHP-FPM / Apache / IIS app pool'larını yeniden başlatın** ve script'i tekrar çalıştırın.

## 8. Bugün için önerilen plan

1. v1.3.0 script'lerini çalıştırın: `NOT PATCHED` / `NOT CONFIRMED` runtime'ları, `Interim:` satırlarını ve paket kaynaklarını listeleyin.
2. Upstream'i takip eden sunucular (php.net, Remi, Sury, resmi imajlar, Windows): 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12'ye güncelleyin, FPM / Apache / IIS app pool'larını **yeniden başlatın**, imajları yeniden derleyip **yeniden deploy edin**. Script'i tekrar çalıştırın (`Running: LOADED`).
3. Dağıtım paketleri (RHEL/Rocky/Alma, Ubuntu): üretici paketi CVE'leri listeleyene kadar geçici önlemleri cgroup bellek sınırıyla **birlikte** uygulayın ve maruziyeti kısıtlayın.
4. Bellek tükenmesi ve çökme kurallarını (Wazuh 109627–109629, Sigma), ModSecurity gövde sınırlarını + 9109622'yi log modunda ve davranışsal kuralları açın.
5. Maruz kalmış sunucularda av: 20 Ekim'den beri `in Unknown on line 0` bellek hataları ve worker çökmeleri, webshell (YARA), yeni `.user.ini`/`.htaccess`, cron job ve hesaplar.
6. Upstream-EOL dallar (≤ 8.1): yükseltme, üretici/ESM backport'u veya izolasyon.

## 9. Lab notları

### 9a. Yama analizi (21 Ekim, yayın sonrası) — yalnızca resmi yama ve regresyon testleri

Yöntem: `php-8.3.35..php-8.3.36` diff'i (düzeltme commit'i `3c832b523e`, "Avoid state corruption via bailout",
dört dalda aynı yama); PHP'nin **kendi** yeni `.phpt` regresyon testleri, yamasız 8.3.35 ve yamalı 8.3.36'nın
debug + ASan build'lerinde (php-cgi) çalıştırıldı. Exploit kodu yazılmadı, kullanılmadı.

* Yamanın değiştirdikleri: istek başlatma sırasında bellek tükenmesi artık yarım kurulmuş durumdan `longjmp`
  ile çıkmıyor; istek ayrıştırıcısı (`main/rfc1867.c`, `main/php_variables.c`, `main/SAPI.c`) yumuşak sınırı
  kontrol edip temiz şekilde duruyor; bir sonraki isteğe taşınabilecek global'ler sıfırlanıyor (`$_GET/$_POST/...`
  alanları, son hata, modül durumu); multipart ayrıştırıcı yalnızca `Content-Disposition` / `Content-Type` part
  başlıklarını tutuyor, tekrarları yok sayıyor; upload-progress işleyicisi istek başlamadan sınıf çözümlemiyor,
  kullanıcı kodu (`__wakeup`, autoload) çalıştırmıyor ve `session_start()` çağırmayan script'lerde geride
  `$_SESSION` bırakmıyor.
* Yamasız 8.3.35: uygulanabilir 27 yeni testten 5'i başarısız (iki multipart part-başlık seli testi → ayrıştırma
  sırasında bellek tükenmesi; üç upload-progress session testi). Yamalı 8.3.36: 27/27 başarılı.
* Geçici önlemler, PHP'nin regresyon testi gövdesiyle (tek alan, 600.000 başlık satırı, 3 MB), yamasız 8.3.35
  php-cgi: varsayılan ayarlar → `Allowed memory size of 134217728 bytes exhausted … in Unknown on line 0`;
  `post_max_size=8M` → aynı; `session.upload_progress.enabled=0` → aynı; `memory_limit=-1` → istek tamamlandı
  (debug build'de ≈218 MB tepe). Yamalı 8.3.36, varsayılan ayarlarla: ≈2 MB tepe.
* **PHP-FPM, script mevcut olmasa bile istek gövdesini ayrıştırıyor.** Yamasız 8.3.35 php-fpm (unix socket, yalnızca lab):
  upload-progress alanı içeren multipart istek var olmayan bir `.php`'ye gönderildiğinde session dosyası yazıldı, ardından
  `404 File not found` döndü; PHP'nin regresyon testi gövdesi var olmayan `.php`'ye gönderildiğinde
  `Allowed memory size … in Unknown on line 0` oluştu ve worker kapandı. Apache `SetHandler "proxy:unix:…|fcgi://…"`
  (RHEL/Rocky varsayılan `php.conf`) veya `try_files` olmadan nginx `fastcgi_pass` ile **herhangi bir `/rastgele.php` adresi
  PHP'ye ulaşır**. Çözüm web sunucusunda: var olmayan `.php`'yi reddedin (Apache: `<FilesMatch "\.php$">` içinde
  `<If "! -f %{REQUEST_FILENAME}">Require all denied</If>`, nginx: `try_files $uri =404;`) ve gerçekten kullandığınız PHP
  giriş noktalarını izin listesine alın.
* Testin sınırları: debug + ASan build'ler (bellek hesabı release build'lerden farklı); tek istekli CGI —
  kalıcı worker'larda istekler arası yeniden kullanım (CVE-2026-109619) yeniden üretilmedi.

### 9b. Açıklama öncesi: upload-progress mekanizması (Ubuntu 24.04, PHP 8.3.6, mod_php ve yerleşik sunucu)

Flatt Security'nin işaret ettiği *mekanizmayı* test ettik — açığın kendisini değil:
* `PHP_SESSION_UPLOAD_PROGRESS` adlı alan içeren bir multipart istek, hedef script `session_start()`
  **hiç çağırmasa bile** PHP'nin, istemcinin seçtiği session ID ile bir session dosyası oluşturmasına yol açtı (`session.use_strict_mode=Off`).
* `session.use_strict_mode=On` iken PHP ilerleme verisini yine yazdı, yalnızca rastgele bir ID ile → strict mode mekanizmayı durdurmuyor.
* `session.upload_progress.enabled=0` iken session dosyası oluşmadı.
* Varsayılan `session.upload_progress.cleanup=On` ile session dosyası boş olarak kaldı.
* Var olmayan bir `.php` yoluna (404) yapılan istek mekanizmayı **mod_php ve yerleşik sunucuda** tetiklemedi; orada web
  sunucusu önce dosyayı kontrol ediyor. **Proxy handler arkasındaki PHP-FPM için bu geçerli değil** — bkz. §9a.
* ModSecurity 2.9: log kuralları yalnızca alanı taşıyan multipart isteklerde tetiklendi; normal yüklemeler işaretlenmedi; engelleme varyantı 403 döndü.
* ModSecurity 2.9.7 (v1.3.0): 9109622, 1.000 part-başlık satırı içeren multipart isteklerde (dosyalı ve dosyasız part) tetiklendi, normal yüklemede tetiklenmedi; PHP'nin 3 MB'lık regresyon testi gövdesi, önerilen gövde sınırı yapılandırması tarafından PHP'ye ulaşmadan reddedildi (HTTP 400).

## 10. Kaynaklar

* PHP — 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 güvenlik sürümleri (21 Ekim 2026): https://www.php.net/archive/2026.php#2026-10-21-1
* PHP kaynak kodu — "Avoid state corruption via bailout" düzeltme commit'i (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp): https://github.com/php/php-src/commit/3c832b523ee13b1a010177d2ff84aea18be0015e
* PHP — Upcoming Critical PHP Security Release (20 Ekim 2026): https://www.php.net/archive/2026.php#2026-10-20-1
* GMO Flatt Security — php2shell özeti ve öneriler (Japonca, 21 Ekim'de güncellendi): https://blog.flatt.tech/entry/php2shell
* Sansec — Critical PHP RCE: https://sansec.io/research/php2shell
* Huntress — Rapid Response: https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
* The Hacker News: https://thehackernews.com/2026/10/php2shell-two-unpatched-critical-php.html
* Phoenix Security: https://phoenix.security/php-core-rce-cve-2026-109618-109619-critical-remote-code-execution/
* PHP kılavuzu — Session Upload Progress: https://www.php.net/manual/en/session.upload-progress.php
* Red Hat RHSA-2026:22143 · Rocky RLSA-2026:34354 · Debian DSA-6255-1 · Ubuntu USN-8564-1 (yama gecikmesi örnekleri)
* PHP EOL Backportları — PHP 5.6, 7.x, 8.0, 8.1 için topluluk güvenlik yamaları (CVE-2026-109618 / CVE-2026-109619): https://github.com/Anton-Barinov/php2shell-patches

## 11. ORBITRON üzerinden çalıştırma

ORBITRON müşterileri aynı incelemeyi hazır bir komut playbook'u olarak çalıştırabilir:
*PHP exposure and behavior investigation*. Playbook, filo genelinde salt okunur PHP / web worker
envanteri ve sınırlı kanıt toplama yapar.

![ORBITRON playbook: PHP exposure and behavior investigation](docs/images/orbitron-php2shell-investigation-playbook.png)

Playbook işletim sistemine göre dallanır. Linux sunucular ve container host'ları için PHP
envanteri, worker'lar, dosyalar, bağlantılar ve Docker bilgisi toplanır. Windows web sunucuları
için PHP/IIS envanteri, worker'lar, dosyalar ve bağlantılar toplanır. Her dal kanıtı ve kapsam
raporunu döndürür. Desteklenmeyen işletim sistemleri de ayrıca raporlanır, böylece kör noktalar
görünür kalır.

`scripts/` altındaki script'ler bağımsızdır, ORBITRON gerektirmez.

## Sorumluluk reddi ve lisans

Savunma amaçlı, olduğu gibi ve garanti olmaksızın sunulmuştur. Script ve kuralları üretimde kullanmadan
önce kendi ortamınızda doğrulayın. Bu repoda exploit kodu yoktur ve yayınlanmayacaktır. Script ve
kurallar: MIT Lisansı (bkz. [LICENSE](LICENSE)). © 2026 ORBITRON.
