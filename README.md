# extract-tlsscan-hostnames
Extract TLS-Scan Hostnames from Certificate Records

Этот Python-скрипт извлекает имена хостов и IP-адреса из JSON-файла, полученного от сканера TLS, такого как `tls-scan`. Скрипт обрабатывает информацию о сертификатах, проверяет наличие необходимых ключей ("cert", "subject", "commonName", "subjectAltName") и извлекает имена хостов. Он фильтрует ненужные префиксы и выводит отсортированный список имен хостов и IP-адресов в консоль. <br><br>
Работоспособность скрипта:<br>
Amazon AWS - ✅<br>
Google Cloud Platform - 🤷‍♂️<br>
Azure - 🤷‍♂️<br><br>

Скрипт может быть полезен для автоматизации анализа безопасности, создания документации и поиска/замены имен хостов в проектах.<br>
![изображение](https://github.com/user-attachments/assets/00a49519-7ac9-40d2-890f-99c98b7285e8)
