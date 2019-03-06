#!/bin/sh

python sim_IoT_dev.py -s 10 &
python sim_IoT_dev.py -s 7 &
python sim_IoT_dev.py -s 7 &
python sim_IoT_dev.py -s 5 &
python sim_IoT_dev.py -s 1 &
python sim_IoT_dev.py -s 5 &
python sim_IoT_dev.py -s 1 &
python sim_IoT_dev.py -s 2 &
python sim_IoT_dev.py -s 1 &
python sim_IoT_dev.py -s 1 &
sleep 365m; python visualization.py > block_log.txt