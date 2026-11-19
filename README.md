# Wi-Fi Happ

Пробная подписка на публичные прокси для домашнего интернета. Один раз добавьте в Happ [адрес подписки](https://theblady.github.io/happ-wifi-subscription/happ.txt). GitHub пересобирает список раз в два часа, а Happ обновляет его по тому же адресу.

Подписка содержит до 20 узлов с наименьшей измеренной задержкой HTTPS через туннель с домашнего Wi-Fi. В Happ они показаны по стране выходного IP. GitHub перепроверяет доступность кандидатов каждые два часа. Если новый список получился пустым, GitHub Pages продолжит отдавать последнюю опубликованную подборку.

Источники — [igareck](https://github.com/igareck/vpn-configs-for-russia), [wlunlocker](https://github.com/wlunlocker/vpn-configs), [morpheusadam](https://github.com/morpheusadam/v2ray-config) и [barry-far](https://github.com/barry-far/V2ray-Config). Новые узлы добавляются после локального замера. GitHub подтверждает доступность из своей сети, а при отборе использует задержку из файла `wifi-baseline.json`.

Расписание использует 17-ю минуту каждого второго часа по UTC. Ручной запуск доступен во вкладке Actions. В `status.json` публикуются время сборки, число кандидатов, результаты проверок и страны, вошедшие в подписку. GitHub может [приостановить расписание после 60 дней без активности в публичном репозитории](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule). Расписание можно включить заново во вкладке Actions.

Для запуска локально нужны Python 3.10+, Mihomo и curl.

```sh
python -m unittest -v
python build.py --mihomo /path/to/mihomo
```

Для повторного замера с домашнего подключения укажите интерфейс Wi-Fi. На Windows имя интерфейса можно посмотреть командой `Get-NetAdapter`.

```sh
python build.py --mihomo /path/to/mihomo --interface "<имя интерфейса>" --record-wifi-baseline wifi-baseline.json
```

В настройках GitHub Pages выберите **GitHub Actions** как источник. После успешного workflow адрес подписки имеет вид `https://<owner>.github.io/<repository>/happ.txt`.
