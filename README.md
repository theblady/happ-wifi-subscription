# Wi-Fi Happ

Пробная подписка на публичные прокси для домашнего интернета. Добавьте URL файла `happ.txt` в Happ один раз. GitHub пересобирает список раз в два часа, а Happ обновляет его по тому же адресу.

Подписка содержит до 20 узлов с наименьшей задержкой HTTPS через туннель. В Happ они показаны по стране выходного IP. Если новый список получился пустым, GitHub Pages продолжит отдавать последнюю опубликованную подборку.

Источники — [igareck](https://github.com/igareck/vpn-configs-for-russia), [wlunlocker](https://github.com/wlunlocker/vpn-configs), [morpheusadam](https://github.com/morpheusadam/v2ray-config) и [barry-far](https://github.com/barry-far/V2ray-Config). Замеры выполняет раннер GitHub. Задержка и доступность с домашнего Wi-Fi зависят от провайдера.

Расписание использует 17-ю минуту каждого второго часа по UTC. Ручной запуск доступен во вкладке Actions. В `status.json` публикуются время сборки, число кандидатов, результаты проверок и страны, вошедшие в подписку. GitHub может [приостановить расписание после 60 дней без активности в публичном репозитории](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule). Расписание можно включить заново во вкладке Actions.

Для запуска локально нужны Python 3.10+, Mihomo и curl.

```sh
python -m unittest -v
python build.py --mihomo /path/to/mihomo
```

В настройках GitHub Pages выберите **GitHub Actions** как источник. После успешного workflow адрес подписки имеет вид `https://<owner>.github.io/<repository>/happ.txt`.
