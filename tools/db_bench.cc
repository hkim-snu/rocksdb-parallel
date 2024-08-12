//  Copyright (c) 2013-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#ifndef GFLAGS
#include <cstdio>
int main() {
  fprintf(stderr, "Please install gflags to run rocksdb tools\n");
  return 1;
}
#else
#include <rocksdb/db_bench_tool.h>

#include <iostream>
#include <map>

#include <sys/time.h>
#include <time.h>

#include <rocksdb/calclock.h>

#define calpercentage(a, b) (((double)a / (double)b) * 100)

#if DOPROFILE
extern unsigned long long delay_write_sleep_time, delay_write_sleep_count;
extern unsigned long long delay_write_cv_wait_time, delay_write_cv_wait_count;

extern unsigned long long handle_buffer_full_time, handle_buffer_full_count;
extern unsigned long long sched_flush_time, sched_flush_count;
extern unsigned long long delay_write_time, delay_write_count;
extern unsigned long long log_sync_wait_time, log_sync_wait_count;

extern unsigned long long join_batch_group_time, join_batch_group_count;
extern unsigned long long wait_mt_writer_time, wait_mt_writer_count;
extern unsigned long long pre_write_time, pre_write_count;
extern unsigned long long write_wal_time, write_wal_count;
extern unsigned long long insert_into_time, insert_into_count;

extern unsigned long long do_write_time, do_write_count;
extern unsigned long long bench_run_time, bench_run_count;

extern unsigned long long proc_kv_comp_time, proc_kv_comp_count;

extern unsigned long long make_input_iter_time, make_input_iter_count;
extern unsigned long long seek_first_time, seek_first_count;
extern unsigned long long add_to_builder_time, add_to_builder_count;
extern unsigned long long next_time, next_count;
extern unsigned long long finish_comp_output_time, finish_comp_output_count;

extern unsigned long long append_compaction_time, append_compaction_count;
extern unsigned long long read_compaction_time, read_compaction_count;
#endif

extern unsigned long long buffer_total_count, buffer_hit_count, buffer_miss_count;

int main(int argc, char** argv) { 
    int result;

    unsigned long long total_time = 0, total_count = 0;
    struct timespec local_time[2];
    clock_gettime(CLOCK_MONOTONIC, &local_time[0]);

	struct timespec tv[2];
	clock_gettime(CLOCK_MONOTONIC, &tv[0]);
	unsigned long long startTime = tv[0].tv_sec*BILLION + tv[0].tv_nsec;

    result = rocksdb::db_bench_tool(argc, argv);

    clock_gettime(CLOCK_MONOTONIC, &local_time[1]);
    calclock(local_time, &total_time, &total_count);

	//printf("start time { %llu } duration { %llu } count { %llu } \n\n", startTime, total_time, total_count);

#if DOPROFILE

	// CompactionJob::ProcessKeyValueCompaction ==================================
	printf("\n");
	printf("CompactionJob::ProcessKeyValueCompaction\n");
	printf("========== proc_kv_comp_time: %llu, proc_kv_comp_count: %llu [ %.1f ]\n", proc_kv_comp_time, proc_kv_comp_count, (double)calpercentage(proc_kv_comp_time, do_write_time));

#if 1
	// CompactionJob::ProcessKeyValueCompaction ==================================
	printf("\n");
	printf("ProcessKeyValueCompaction\n");
	printf("========== make_input_iter_time: %llu, make_input_iter_count: %llu [ %.1f / %.1f ]\n", make_input_iter_time, make_input_iter_count, (double)calpercentage(make_input_iter_time, proc_kv_comp_time), (double)calpercentage(make_input_iter_time, do_write_time));
	printf("========== seek_first_time: %llu, seek_first_count: %llu [ %.1f / %.1f ]\n", seek_first_time, seek_first_count, (double)calpercentage(seek_first_time, proc_kv_comp_time), (double)calpercentage(seek_first_time, do_write_time));
	//printf("========== key_compare_time: %llu, key_compare_count: %llu [ %.1f / %.1f ]\n", key_compare_time, key_compare_count, (double)calpercentage(key_compare_time, proc_kv_comp_time), (double)calpercentage(key_compare_time, do_write_time));
	//printf("========== open_comp_output_time: %llu, open_comp_output_count: %llu [ %.1f / %.1f ]\n", open_comp_output_time, open_comp_output_count, (double)calpercentage(open_comp_output_time, proc_kv_comp_time), (double)calpercentage(open_comp_output_time, do_write_time));
	printf("========== builder_add_time: %llu, builder_add_count: %llu [ %.1f / %.1f ]\n", add_to_builder_time, add_to_builder_count, (double)calpercentage(add_to_builder_time, proc_kv_comp_time), (double)calpercentage(add_to_builder_time, do_write_time));
	printf("append_compaction_time { %llu } append_compaction_count { %llu } [ %.1f / %.1f ] \n\n", append_compaction_time, append_compaction_count, (double)calpercentage(append_compaction_time, proc_kv_comp_time), (double)calpercentage(append_compaction_time, do_write_time));
	printf("========== iter_next_time: %llu, iter_next_count: %llu [ %.1f / %.1f ]\n", next_time, next_count, (double)calpercentage(next_time, proc_kv_comp_time), (double)calpercentage(next_time, do_write_time));
	printf("read_compaction_time { %llu } read_compaction_count { %llu } [ %.1f / %.1f ] \n\n", read_compaction_time, read_compaction_count, (double)calpercentage(read_compaction_time, proc_kv_comp_time), (double)calpercentage(read_compaction_time, do_write_time));
	printf("========== finish_comp_output_time: %llu, finish_comp_output_count: %llu [ %.1f / %.1f ]\n", finish_comp_output_time, finish_comp_output_count, (double)calpercentage(finish_comp_output_time, proc_kv_comp_time), (double)calpercentage(finish_comp_output_time, do_write_time));
#endif

#if 1
    // DBImpl::DelayWrite ==================================
    printf("\n");
    printf("DBImpl::DelayWrite\n");
    printf("========== delay_write_sleep_time: %llu, delay_write_sleep_count: %llu [ %.1f ]\n", delay_write_sleep_time, delay_write_sleep_count, (double)calpercentage(delay_write_sleep_time, do_write_time));
    printf("========== delay_write_cv_wait_time: %llu, delay_write_cv_wait_count: %llu [ %.1f ]\n", delay_write_cv_wait_time, delay_write_cv_wait_count, (double)calpercentage(delay_write_cv_wait_time, do_write_time));
#endif

#if 0
    // DBImpl::PreprocessWrite ==================================
    printf("\n");
    printf("DBImpl::PreprocessWrite\n");
    printf("========== handle_buffer_full_time: %llu, handle_buffer_full_count: %llu [ %.1f ]\n", handle_buffer_full_time, handle_buffer_full_count, (double)calpercentage(handle_buffer_full_time, do_write_time));
    printf("========== sched_flush_time: %llu, sched_flush_count: %llu [ %.1f ]\n", sched_flush_time, sched_flush_count, (double)calpercentage(sched_flush_time, do_write_time));
    printf("========== delay_write_time: %llu, delay_write_count: %llu [ %.1f ]\n", delay_write_time, delay_write_count, (double)calpercentage(delay_write_time, do_write_time));
    printf("========== log_sync_wait_time: %llu, log_sync_wait_count: %llu [ %.1f ]\n", log_sync_wait_time, log_sync_wait_count, (double)calpercentage(log_sync_wait_time, do_write_time));
#endif

    // DBImpl::PipelinedWriteImpl ==================================
    printf("\n");
    printf("DBImpl::PipelinedWriteImpl\n");
    printf("========== join_batch_group_time: %llu, join_batch_group_count: %llu [ %.1f ]\n", join_batch_group_time, join_batch_group_count, (double)calpercentage(join_batch_group_time, do_write_time));
    printf("========== wait_mt_writer_time: %llu, wait_mt_writer_count: %llu [ %.1f ]\n", wait_mt_writer_time, wait_mt_writer_count, (double)calpercentage(wait_mt_writer_time, do_write_time));
    printf("========== pre_write_time: %llu, pre_write_count: %llu [ %.1f ]\n", pre_write_time, pre_write_count, (double)calpercentage(pre_write_time, do_write_time));
    printf("========== write_wal_time: %llu, write_wal_count: %llu [ %.1f ]\n", write_wal_time, write_wal_count, (double)calpercentage(write_wal_time, do_write_time));
    printf("========== insert_into_time: %llu, insert_into_count: %llu [ %.1f ]\n", insert_into_time, insert_into_count, (double)calpercentage(insert_into_time, do_write_time));


    // WriteUniqueRandom ==================================
    printf("\n");
    printf("WriteUniqueRandom\n");
    printf("========== do_write_time: %llu, do_write_count: %llu [ %.1f ]\n", do_write_time, do_write_count, (double)calpercentage(do_write_time, total_time));

    // benchmark.Run ==================================
    printf("\n");
    printf("benchmark.Run\n");
    printf("========== bench_run_time: %llu, bench_run_count: %llu [ %.1f ]\n", bench_run_time, bench_run_count, (double)calpercentage(bench_run_time, total_time));
    // rocksdb::db_bench_tool ==================================

#endif

    printf("\n");
    printf("rocksdb::db_bench_tool\n");
    printf("========== total_time: %llu, total_count: %llu [ %.1f ]\n", total_time, total_count, (double)calpercentage(total_time, total_time));
	printf("start time { %llu }\n", startTime);
    printf("\n");

    printf("buffer_total_count { %llu } buffer_hit_count { %llu } buffer_miss_count { %llu } \n", buffer_total_count, buffer_hit_count, buffer_miss_count);


	return result;	
	//return rocksdb::db_bench_tool(argc, argv); 

}
#endif  // GFLAGS
