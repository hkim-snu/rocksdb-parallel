#!/bin/bash

NUM_THREAD=16
NUM_COMPACTIONS=2
NUM_FLUSHES=1
#let NUM=(625000/$NUM_THREAD)
NUM=625000

	rm /mnt/nvme/rocksdb/*

        sudo echo 1 > /proc/sys/vm/drop_caches;
        sudo echo 2 > /proc/sys/vm/drop_caches;
        sudo echo 3 > /proc/sys/vm/drop_caches;

	echo 'time ./db_bench --benchmarks=fillrandom,waitforcompaction,stats --db=/mnt/nvme/rocksdb --use_direct_io_for_flush_and_compaction --use_direct_reads --num='$NUM' --value_size=16384 --block_size=4096 --compression_type=none --compression_ratio=1 --use_existing_db=0 --threads='$NUM_THREAD' --max_background_compactions='$NUM_COMPACTIONS' --max_background_flushes='$NUM_FLUSHES

	time ./db_bench --benchmarks=fillrandom,stats --db=/mnt/nvme/rocksdb --use_direct_io_for_flush_and_compaction=true --use_direct_reads=true --num=$NUM --value_size=16384 --block_size=4096 --compression_type=none --compression_ratio=1 --use_existing_db=0 --threads=$NUM_THREAD --max_background_compactions=$NUM_COMPACTIONS --max_background_flushes=$NUM_FLUSHES
	#time ./db_bench --benchmarks=filluniquerandom,stats --db=/mnt/nvme/rocksdb --use_direct_io_for_flush_and_compaction --use_direct_reads --num=$NUM --value_size=16384 --block_size=4096 --compression_type=none --compression_ratio=1 --use_existing_db=0 --threads=$NUM_THREAD --max_background_compactions=$NUM_COMPACTIONS --max_background_flushes=$NUM_FLUSHES
	
