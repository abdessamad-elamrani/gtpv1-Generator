#!/bin/bash

#cat improved.bash
#!/bin/bash


cpus=52
total_tunnels=40000012
max_teid=$((total_tunnels / cpus)) # max teid per SGW
teid_gen_range=57693    # how many teid to create for every range
num_ranges=$(($((max_teid / teid_gen_range))+1)) # number of teid ranges : 1-4m, 4m-8m, 8m-16m  >> in this case its 3

echo 
echo '************  starting now, current time : '$(date)'**************'
echo 
echo '	Total required GTP Tunnels : '$total_tunnels
echo '  Maximum TEID for every sgw/pgw: '$total_tunnels' / '$cpus' = '$max_teid
echo '  Pcaps are generated by '$teid_gen_range' teids range, so its '$max_teid' / '$teid_gen_range' = '$num_ranges
echo

ref_time=$(date +%s)

gsn_id=0
counter=0

# Read the entire mapping.cache file into an array
mapfile -t lines < <(jq -c '.[]' mapping.cache)

# Start by getting the initial number of iterations


current_index=0

range=0

while (( range < num_ranges ));do #for every range of teids, generate 52 pcap

    teidstart=$(($((range*teid_gen_range))+1))
    #teidstop=$(((range+1)*teid_gen_range))
    teidstop=$(( (range+1) * teid_gen_range > max_teid ? max_teid : (range+1) * teid_gen_range ))

    current_time=$(date +%s)

    echo '------------------------------------------------------------------------------------------'
    echo 'We will generate next range of TEIDs for all SGW/PGW, range:  '$range' from: '$teidstart' to '$teidstop
    echo 'Time spent in last range ieration : '$((current_time - ref_time))
    echo '------------------------------------------------------------------------------------------' 
    
    ref_time=$(date +%s)

    # now we know the range, trigger the first 26 range
    
    echo '              ------------------------------------------------------------'
    echo '              starting the FIRST 26 sgw/pgw python instance for this range'
    echo '              ------------------------------------------------------------'
    for ((i=0; i<26; i++)); do #for every sgw/pgw

        # Extract sgw and pgw
        sgw=$(echo ${lines[$i]} | jq -r '.sgw')
        pgw=$(echo ${lines[$i]} | jq -r '.pgw')
        # Call the python script
        python3 generate_single_pair.py "$sgw" "$pgw" "$teidstart" "$teidstop" "output_${range}_${i}.pcap" "$i" &

    done

    # Wait for all background processes to complete
    wait

    echo '              ------------------------------------------------------------'
    echo '              starting the SECOND 26 sgw/pgw python instance for this range'
    echo '              ------------------------------------------------------------'
    # next 26 range
    for ((i=26; i<52; i++)); do #for every sgw/pgw

        # Extract sgw and pgw
        sgw=$(echo ${lines[$i]} | jq -r '.sgw')
        pgw=$(echo ${lines[$i]} | jq -r '.pgw')
        # Call the python script
        python3 generate_single_pair.py "$sgw" "$pgw" "$teidstart" "$teidstop" "output_${range}_${i}.pcap" "$i" &

    done

    # Wait for all background processes to complete
    wait

    sleep 1
      
    mergecap -w combined_range_"$range".pcap output_"$range"_*.pcap
    rm output_"$range"_*.pcap

    range=$((range+1))
done
