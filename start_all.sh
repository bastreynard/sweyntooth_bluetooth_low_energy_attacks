#!/bin/bash
COM='COM3'
BT_ADDR='00:1B:66:12:6D:44'
echo "Run test ? 0-10"
read index
case "$index" in
    "1")
        python CC_connection_req_crash.py $COM $BT_ADDR
        ;;
    "2")
        python CC2640R2_public_key_crash.py $COM $BT_ADDR
        ;;
    "3")
        python DA14580_exploit_att_crash.py $COM $BT_ADDR
        ;;
    "4")
        python DA14680_exploit_silent_overflow.py $COM $BT_ADDR
        ;;
    "5")
        python invalid_channel_map.py $COM $BT_ADDR
        ;;
    "6")
        python link_layer_length_overflow.py $COM $BT_ADDR
        ;;
    "7")
        python llid_deadlock.py $COM $BT_ADDR
        ;;
    "8")
        python Microchip_invalid_lcap_fragment.py $COM $BT_ADDR
        ;;
esac