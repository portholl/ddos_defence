# A method for detecting and preventing Distributed Denial of Service attacks on controllers in software-defined networks using machine learning algorithms (ddos_defence_
Сначала запускается контроллер RUNOS с конфигурационным файлом runos/runos.json, содержащим параметры OpenFlow-сервера и разработанного приложения guard-app.

[nix-shell:~/runos/build]$ ./runos -c ../runos.json


После запуска контроллера стартует внешний модуль анализа на Python. Он считывает статистику потоков, вычисляет признаки, применяет модель машинного обучения, обновляет TVC, формирует решение о состоянии потока, сохраняет результаты в CSV.

python3 -m runos_guard.main


Затем запускается mininet с желаемой топологией сети.

sudo mn --controller=remote,ip=172.20.6.2, port=6653 --switch=ovs, protocol=OpenFlow13 --topo single,3


Система функционирует в течение заранее заданного интервала времени. В процессе работы Python-модуль принимает решения в реальном времени, а все результаты записываются в лог.
