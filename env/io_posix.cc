//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifdef ROCKSDB_LIB_IO_POSIX
#include "env/io_posix.h"
#include <errno.h>
#include <fcntl.h>
#include <algorithm>
#if defined(OS_LINUX)
#include <linux/fs.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef OS_LINUX
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#endif
#include "env/posix_logger.h"
#include "monitoring/iostats_context_imp.h"
#include "port/port.h"
#include "rocksdb/slice.h"
#include "util/coding.h"
#include "util/string_util.h"
#include "util/sync_point.h"

#if defined(OS_LINUX) && !defined(F_SET_RW_HINT)
#define F_LINUX_SPECIFIC_BASE 1024
#define F_SET_RW_HINT         (F_LINUX_SPECIFIC_BASE + 12)
#endif

#include <rocksdb/calclock.h>
#include <malloc.h>

#define BUFSIZE (1024*1024*2)

//extern unsigned long long startTime;
unsigned long long append_compaction_time=0, append_compaction_count=0;
unsigned long long read_compaction_time=0, read_compaction_count=0;

unsigned long long lock_time=0, lock_count=0;

unsigned long long buffer_total_count=0, buffer_hit_count=0, buffer_miss_count=0;

#define LOCK_PROFILE
#define LOCK

namespace rocksdb {

// A wrapper for fadvise, if the platform doesn't support fadvise,
// it will simply return 0.
int Fadvise(int fd, off_t offset, size_t len, int advice) {
#ifdef OS_LINUX
  return posix_fadvise(fd, offset, len, advice);
#else
  return 0;  // simply do nothing.
#endif
}

namespace {
size_t GetLogicalBufferSize(int __attribute__((__unused__)) fd) {
#ifdef OS_LINUX
  struct stat buf;
  int result = fstat(fd, &buf);
  if (result == -1) {
    return kDefaultPageSize;
  }
  if (major(buf.st_dev) == 0) {
    // Unnamed devices (e.g. non-device mounts), reserved as null device number.
    // These don't have an entry in /sys/dev/block/. Return a sensible default.
    return kDefaultPageSize;
  }

  // Reading queue/logical_block_size does not require special permissions.
  const int kBufferSize = 100;
  char path[kBufferSize];
  char real_path[PATH_MAX + 1];
  snprintf(path, kBufferSize, "/sys/dev/block/%u:%u", major(buf.st_dev),
           minor(buf.st_dev));
  if (realpath(path, real_path) == nullptr) {
    return kDefaultPageSize;
  }
  std::string device_dir(real_path);
  if (!device_dir.empty() && device_dir.back() == '/') {
    device_dir.pop_back();
  }
  // NOTE: sda3 does not have a `queue/` subdir, only the parent sda has it.
  // $ ls -al '/sys/dev/block/8:3'
  // lrwxrwxrwx. 1 root root 0 Jun 26 01:38 /sys/dev/block/8:3 ->
  // ../../block/sda/sda3
  size_t parent_end = device_dir.rfind('/', device_dir.length() - 1);
  if (parent_end == std::string::npos) {
    return kDefaultPageSize;
  }
  size_t parent_begin = device_dir.rfind('/', parent_end - 1);
  if (parent_begin == std::string::npos) {
    return kDefaultPageSize;
  }
  if (device_dir.substr(parent_begin + 1, parent_end - parent_begin - 1) !=
      "block") {
    device_dir = device_dir.substr(0, parent_end);
  }
  std::string fname = device_dir + "/queue/logical_block_size";
  FILE* fp;
  size_t size = 0;
  fp = fopen(fname.c_str(), "r");
  if (fp != nullptr) {
    char* line = nullptr;
    size_t len = 0;
    if (getline(&line, &len, fp) != -1) {
      sscanf(line, "%zu", &size);
    }
    free(line);
    fclose(fp);
  }
  if (size != 0 && (size & (size - 1)) == 0) {
    return size;
  }
#endif
  return kDefaultPageSize;
}
} //  namespace

/*
 * DirectIOHelper
 */
#ifndef NDEBUG
namespace {

bool IsSectorAligned(const size_t off, size_t sector_size) {
  return off % sector_size == 0;
}

bool IsSectorAligned(const void* ptr, size_t sector_size) {
  return uintptr_t(ptr) % sector_size == 0;
}

}
#endif

// hkim
#if 1
MyReadQueue::MyReadQueue() {
	// debugging
	printf("[%s::%s::%d] MyReadQueue Created\n", __FILE__, __func__, __LINE__);

    read_file_map = new READ_FILE_MAP();
    buffer_data_count = 0;

    prefetch_target_file = "";
    prefetch_start_offset = 0;

}

MyReadQueue::~MyReadQueue() {
	// debugging
	printf("[%s::%s::%d] MyReadQueue Destroyed\n", __FILE__, __func__, __LINE__);

    if (read_file_map != nullptr)
        delete read_file_map;
}

bool MyReadQueue::AddFileToReadQueue(const std::string fname, int fd, bool use_direct_io, size_t alignment) {
	bool result = true;

#ifdef LOCK_PROFILE
#endif

	// for checking function call
	//printf("[%s::%s::%d] AddFile { %s } fd { %d } \n", __FILE__, __func__, __LINE__, fname.c_str(), fd);

    //int new_fd = OpenFile(fname, alignment);
    //MyReadFileInfo* ptrRFInfo = new MyReadFileInfo(fname, new_fd, use_direct_io, alignment);

    MyReadFileInfo* ptrRFInfo = new MyReadFileInfo(fname, fd, use_direct_io, alignment);

	std::pair<std::map<std::string, MyReadFileInfo*>::iterator, bool> ret;
#ifdef LOCK
    mutex_.lock();
#endif
	ret = read_file_map->insert(std::pair<std::string, MyReadFileInfo*>(fname, ptrRFInfo));
#ifdef LOCK
    mutex_.unlock();
#endif
	if (ret.second == false) {
		printf("[%s::%s::%d] key { %s } already exist!!!\n", __FILE__, __func__, __LINE__, fname.c_str());
	}


	
    return result;
}

bool MyReadQueue::RemoveFileFromReadQueue(const std::string fname) {
	bool result = true;
	// for checking function call
	//printf("[%s::%s::%d] RemoveFile { %s } \n", __FILE__, __func__, __LINE__, fname.c_str());

    std::map<std::string, MyReadFileInfo*>::iterator readIt;
#ifdef LOCK
    mutex_.lock();
#endif
    readIt = read_file_map->find(fname);
    if (readIt != read_file_map->end()) {
        close((readIt->second)->GetFD());
        for (auto e : *((readIt->second)->GetFileBuffer())) {
            delete (e.second).second;
        }
        delete (readIt->second);
        read_file_map->erase(readIt);
    }
#ifdef LOCK
    mutex_.unlock();
#endif
	return result;
}

void MyReadQueue::UpdateFileOffset(const std::string fname, uint64_t offset) {
    MyReadFileInfo* info = nullptr;

    // find file info from read_queue
	std::map<std::string, MyReadFileInfo*>::iterator it;
#ifdef LOCK
    mutex_.lock();
#endif
	it = read_file_map->find(fname);
    if (it != read_file_map->end()) {
        info = it->second;
        // set to next offset
        if ((info->GetCurOffset() < offset))
            info->SetCurOffset(offset);
    }
#ifdef LOCK
        mutex_.unlock();
#endif
}

std::string MyReadQueue::SelectFileToPrefetch() {

	std::string selected_filename = "";

#ifdef LOCK
    mutex_.lock();
#endif

    for (auto e : *read_file_map) {
        uint64_t offset = (e.second)->GetCurOffset();
        uint64_t filesize = (e.second)->GetFilesize();

        //printf("[%s::%s::%d] offset { %lu } filesize { %lu } \n", __FILE__, __func__, __LINE__, offset, filesize);

        if (offset < filesize) {
            selected_filename = e.first;
            //printf("[%s::%s::%d] selected_filename { %s } \n", __FILE__, __func__, __LINE__, selected_filename.c_str());
            break;
        }
    }

#ifdef LOCK
    mutex_.unlock();
#endif

	return selected_filename;
}

// calling when foreground goes to sleep
void MyReadQueue::PrefetchQueueData() {
	// read by readahead_
	// until size reaches filesize_

	// queue empty -> nothing to do
	if (IsEmpty()) {
		return;
	}

	// select file from queue to prefetch data
	std::string file_to_read = SelectFileToPrefetch();
    MyReadFileInfo* info = nullptr;

    if (file_to_read == "") {
        return;
    }
    else {
        std::map<std::string, MyReadFileInfo*>::iterator it;
#ifdef LOCK
        mutex_.lock();
#endif
        it = read_file_map->find(file_to_read);
        if (it != read_file_map->end()) {
	        //printf("[%s::%s::%d] filename { %s } \n", __FILE__, __func__, __LINE__, file_to_read.c_str());
            info = it->second;
        }

        if (!info->IsDirectIO()) {
#ifdef LOCK
        mutex_.unlock();
#endif
            return;
        }

        int fd = info->GetFD();
        uint64_t start_offset = info->GetCurOffset();
        uint64_t offset = info->GetCurOffset();
        ssize_t r = -1;
        ssize_t total_read = 0;
        size_t left = info->GetReadahead();
        uint64_t filesize = info->GetFilesize();
#ifdef LOCK
        mutex_.unlock();
#endif

        //printf("[%s::%s::%d] filename { %s } fd { %d } start_offset { %lu } offset { %lu } r { %ld } left { %zu }  \n", __FILE__, __func__, __LINE__, file_to_read.c_str(), fd, start_offset, offset, r, left);

        AlignedBuffer alignedBuf;
        alignedBuf.Alignment(info->GetAlignment());
        alignedBuf.AllocateNewBuffer(left);

        while (left > 0) {
            r = pread(fd, alignedBuf.Destination(), left, static_cast<off_t>(offset));
            if (r <= 0) {
                if (r == -1 && errno == EINTR) {
                    continue;
                }
                break;
            }
            alignedBuf.Size(alignedBuf.CurrentSize() + r);
            offset += r;
            left -= r;

            total_read += r;

            // at the end of the file
            if (offset == filesize) {
                //printf("[%s::%s::%d] end of file { %s }  offset { %lu } filesize { %zu } r { %ld }  \n", __FILE__, __func__, __LINE__, file_to_read.c_str(),  offset, info->GetFilesize(), r);
                //read_file_map->erase(file_to_read);
                break;
            }
        }

        if (r < 0) {
            IOError("while pread offset " + ToString(offset) + " len " + ToString((1024*1024*2)), file_to_read.c_str(), errno);
            printf("[%s::%s::%d] while pread fd %d offset from %lu cur %lu len %zu %s %d\n", __FILE__, __func__, __LINE__, fd, start_offset, offset, total_read, file_to_read.c_str(), errno);
            return;
        }

        // copy file data
        //printf("[%s::%s::%d] total_read { %zu } \n", __FILE__, __func__, __LINE__, total_read);
        char* buf = new char[total_read];
        memcpy(buf, alignedBuf.BufferStart(), alignedBuf.CurrentSize());
        
        SIZE_DATA_PAIR size_data_pair;
        size_data_pair.first = total_read;
        size_data_pair.second = buf;

        // update offset - if valid
#ifdef LOCK
        mutex_.lock();
#endif
        it = read_file_map->find(file_to_read);
        if (it != read_file_map->end()) {
            // still valid
	        //printf("[%s::%s::%d] filename { %s } \n", __FILE__, __func__, __LINE__, file_to_read.c_str());
            info = it->second;
            info->SetCurOffset(offset);
        
            //printf("[%s::%s::%d] bufferadd filename { %s } offset { %lu } size { %ld }\n", __FILE__, __func__, __LINE__, file_to_read.c_str(), start_offset, r);

            //printf("[%s::%s::%d] buffersize { %zu }\n", __FILE__, __func__, __LINE__, info->GetFileBuffer()->size());

            info->GetFileBuffer()->insert(std::pair<uint64_t, SIZE_DATA_PAIR> (start_offset, size_data_pair));
            __sync_fetch_and_add(&buffer_total_count, 1);
            IncreaseBufferCount();

            //printf("[%s::%s::%d] buffersize { %zu }\n", __FILE__, __func__, __LINE__, info->GetFileBuffer()->size());
        }
#ifdef LOCK
        mutex_.unlock();
#endif
    }

}

// find and copy pre-fetched data
void MyReadQueue::GetData(const std::string fname, int fd, uint64_t offset, size_t n, Slice* result, char* scratch) {

	//printf("[%s::%s::%d] filename { %s } offset { %lu } size { %zu } \n", __FILE__, __func__, __LINE__, fname.c_str(), offset, n);

	size_t buf_size;

    MyReadFileInfo* info = nullptr;

    // find file info from read_queue
	std::map<std::string, MyReadFileInfo*>::iterator it;
#ifdef LOCK
    mutex_.lock();
#endif
	it = read_file_map->find(fname);
    if (it != read_file_map->end()) {
        info = it->second;
        //printf("[%s::%s::%d] buffersize { %zu }\n", __FILE__, __func__, __LINE__, info.GetFileBuffer()->size());

        if (!info->IsDirectIO()) {
#ifdef LOCK
            mutex_.unlock();
#endif
            return;
        }

        // get buffer to copy pre-fetched data
        DATA_BUFFER_MAP *buffer = info->GetFileBuffer();

        DATA_BUFFER_MAP::iterator mapIt;
        mapIt = buffer->find(offset);

        // find buffered data! just copy
        if (mapIt != buffer->end()) {
            buf_size = (mapIt->second).first;
            memcpy(scratch, (mapIt->second).second, buf_size);

            __sync_fetch_and_add(&buffer_hit_count, 1);

            //printf("[%s::%s::%d] bufferhit filename { %s } offset { %lu } size { %zu } \n", __FILE__, __func__, __LINE__, fname.c_str(), offset, buf_size);

            // erase from the buffer
            delete (mapIt->second).second;
            buffer->erase(mapIt);
            DecreaseBufferCount();
#ifdef LOCK
            mutex_.unlock();
#endif
        } else {
            // set to next offset
            if ((info->GetCurOffset() < (offset + n)))
                info->SetCurOffset(offset + n);
#ifdef LOCK
            mutex_.unlock();
#endif
            __sync_fetch_and_add(&buffer_miss_count, 1);
            //printf("[%s::%s::%d] buffermiss filename { %s } offset { %lu } \n", __FILE__, __func__, __LINE__, fname.c_str(), offset);

            scratch = nullptr;
            buf_size = 0;
        }
    } else {
#ifdef LOCK
        mutex_.unlock();
#endif
        scratch = nullptr;
        buf_size = 0;
    }
	  	
	*result = Slice(scratch, buf_size);

	return;
}
#endif

#if 1
MyWriteQueue::MyWriteQueue() {
	// debugging
	printf("[%s::%s::%d] MyWriteQueue Created\n", __FILE__, __func__, __LINE__);

}

MyWriteQueue::~MyWriteQueue() {
	// debugging
	printf("[%s::%s::%d] MyWriteQueue Destroyed\n", __FILE__, __func__, __LINE__);

}

bool MyWriteQueue::AddFileToWriteQueue(const std::string fname, int fd, bool use_direct_io, size_t alignment) {
	bool result = true;
	
#if 0
	// for checking function call
	//printf("[%s::%s::%d] AddFile { %s }\n", __FILE__, __func__, __LINE__, fname.c_str());
    
	MyWriteFileInfo fileInfo(fname, fd, use_direct_io, alignment);

	std::pair<std::map<std::string, MyWriteFileInfo>::iterator, bool> ret;
	ret = write_file_map.insert(std::pair<std::string, MyWriteFileInfo>(fname, fileInfo));
	if (ret.second == false) {
		//printf("[%s::%s::%d] key { %s } already exist!!!\n", __FILE__, __func__, __LINE__, fname.c_str());
	}
#endif

	return result;
}

bool MyWriteQueue::RemoveFileFromWriteQueue(const std::string fname) {
	bool result = true;

	// for checking function call
	//printf("[%s::%s::%d] RemoveFile { %s } \n", __FILE__, __func__, __LINE__, fname.c_str());

	//write_file_map.erase(fname);

	return result;
}

void MyWriteQueue::FlushQueueData() {

}

void MyWriteQueue::FlushData(const std::string fname, int fd, const Slice& data, uint64_t offset) {

}
#endif
// hkim


/*
 * PosixSequentialFile
 */
PosixSequentialFile::PosixSequentialFile(const std::string& fname, FILE* file,
                                         int fd, const EnvOptions& options)
    : filename_(fname),
      file_(file),
      fd_(fd),
      use_direct_io_(options.use_direct_reads),
      logical_sector_size_(GetLogicalBufferSize(fd_)) {
  assert(!options.use_direct_reads || !options.use_mmap_reads);
}

PosixSequentialFile::~PosixSequentialFile() {
  if (!use_direct_io()) {
    assert(file_);
    fclose(file_);
  } else {
    assert(fd_);
    close(fd_);
  }
}

Status PosixSequentialFile::Read(size_t n, Slice* result, char* scratch) {
  assert(result != nullptr && !use_direct_io());
  Status s;
  size_t r = 0;
  do {
#if 0
	  struct timespec tv[2];
	  clock_gettime(CLOCK_MONOTONIC, &tv[0]);
	  unsigned long long start_ts = tv[0].tv_sec*BILLION + tv[0].tv_nsec;
	  
	  printf("OP_FREAD_START %llu %s\n", start_ts, filename_.c_str());
#endif
    r = fread_unlocked(scratch, 1, n, file_);
#if 0
	clock_gettime(CLOCK_MONOTONIC, &tv[1]);
	unsigned long long end_ts = tv[1].tv_sec*BILLION + tv[1].tv_nsec;

	printf("OP_FREAD_END %llu %s %llu %zu\n", end_ts, filename_.c_str(), (end_ts - start_ts), r);
#endif
  } while (r == 0 && ferror(file_) && errno == EINTR);
  *result = Slice(scratch, r);
  if (r < n) {
    if (feof(file_)) {
      // We leave status as ok if we hit the end of the file
      // We also clear the error so that the reads can continue
      // if a new data is written to the file
      clearerr(file_);
    } else {
      // A partial read with an error: return a non-ok status
      s = IOError("While reading file sequentially", filename_, errno);
    }
  }
  return s;
}

Status PosixSequentialFile::PositionedRead(uint64_t offset, size_t n,
                                           Slice* result, char* scratch) {
  if (use_direct_io()) {
    assert(IsSectorAligned(offset, GetRequiredBufferAlignment()));
    assert(IsSectorAligned(n, GetRequiredBufferAlignment()));
    assert(IsSectorAligned(scratch, GetRequiredBufferAlignment()));
  }
  Status s;
  ssize_t r = -1;
  size_t left = n;
  char* ptr = scratch;
  assert(use_direct_io());
#if 0
  // hkim
  struct timespec local_time[2];
  unsigned long long iotime = 0, iocount = 0;
  // hkim
#endif
  while (left > 0) {
#if 0
	  struct timespec tv[2];
	  clock_gettime(CLOCK_MONOTONIC, &tv[0]);
	  unsigned long long start_ts = tv[0].tv_sec*BILLION + tv[0].tv_nsec;
	  
	  printf("[%s::%d] OP_PREAD_START %llu %s\n", __func__, __LINE__, start_ts, filename_.c_str());
#endif

#if 0
	  clock_gettime(CLOCK_MONOTONIC, &local_time[0]);
#endif
    r = pread(fd_, ptr, left, static_cast<off_t>(offset));
#if 0
	// hkim
	  clock_gettime(CLOCK_MONOTONIC, &local_time[1]);
	  calclock(local_time, &iotime, &iocount);
	printf("thread %d filename %s OP_PREAD from %lu size %zu duration %llu \n", (int)pthread_self(), filename_.c_str(), offset, r, iotime);
	// hkim
#endif

#if 0
	clock_gettime(CLOCK_MONOTONIC, &tv[1]);
	unsigned long long end_ts = tv[1].tv_sec*BILLION + tv[1].tv_nsec;

	printf("OP_PREAD_END %llu %s %llu %lu %zu\n", end_ts, filename_.c_str(), (end_ts - start_ts), offset, r);
#endif

    if (r <= 0) {
      if (r == -1 && errno == EINTR) {
        continue;
      }
      break;
    }
    ptr += r;
    offset += r;
    left -= r;
    if (r % static_cast<ssize_t>(GetRequiredBufferAlignment()) != 0) {
      // Bytes reads don't fill sectors. Should only happen at the end
      // of the file.
      break;
    }
  }
  if (r < 0) {
    // An error: return a non-ok status
    s = IOError(
        "While pread " + ToString(n) + " bytes from offset " + ToString(offset),
        filename_, errno);
  }
  *result = Slice(scratch, (r < 0) ? 0 : n - left);
  return s;
}

Status PosixSequentialFile::Skip(uint64_t n) {
  if (fseek(file_, static_cast<long int>(n), SEEK_CUR)) {
    return IOError("While fseek to skip " + ToString(n) + " bytes", filename_,
                   errno);
  }
  return Status::OK();
}

Status PosixSequentialFile::InvalidateCache(size_t offset, size_t length) {
#ifndef OS_LINUX
  return Status::OK();
#else
  if (!use_direct_io()) {
    // free OS pages
    int ret = Fadvise(fd_, offset, length, POSIX_FADV_DONTNEED);
    if (ret != 0) {
      return IOError("While fadvise NotNeeded offset " + ToString(offset) +
                         " len " + ToString(length),
                     filename_, errno);
    }
  }
  return Status::OK();
#endif
}

/*
 * PosixRandomAccessFile
 */
#if defined(OS_LINUX)
size_t PosixHelper::GetUniqueIdFromFile(int fd, char* id, size_t max_size) {
  if (max_size < kMaxVarint64Length * 3) {
    return 0;
  }

  struct stat buf;
  int result = fstat(fd, &buf);
  assert(result != -1);
  if (result == -1) {
    return 0;
  }

  long version = 0;
  result = ioctl(fd, FS_IOC_GETVERSION, &version);
  TEST_SYNC_POINT_CALLBACK("GetUniqueIdFromFile:FS_IOC_GETVERSION", &result);
  if (result == -1) {
    return 0;
  }
  uint64_t uversion = (uint64_t)version;

  char* rid = id;
  rid = EncodeVarint64(rid, buf.st_dev);
  rid = EncodeVarint64(rid, buf.st_ino);
  rid = EncodeVarint64(rid, uversion);
  assert(rid >= id);
  return static_cast<size_t>(rid - id);
}
#endif

#if defined(OS_MACOSX) || defined(OS_AIX)
size_t PosixHelper::GetUniqueIdFromFile(int fd, char* id, size_t max_size) {
  if (max_size < kMaxVarint64Length * 3) {
    return 0;
  }

  struct stat buf;
  int result = fstat(fd, &buf);
  if (result == -1) {
    return 0;
  }

  char* rid = id;
  rid = EncodeVarint64(rid, buf.st_dev);
  rid = EncodeVarint64(rid, buf.st_ino);
  rid = EncodeVarint64(rid, buf.st_gen);
  assert(rid >= id);
  return static_cast<size_t>(rid - id);
}
#endif

// hkim
#if 0
static void * Thread_ReadWrapper(void *args) {
	PosixRandomAccessFile *pFile = (PosixRandomAccessFile *)args;

	printf("[%s::%s::%d] filename { %s } \n", __FILE__, __func__, __LINE__, (pFile->GetFilename()).c_str());

	return args;
}
#endif

/*
 * PosixRandomAccessFile
 *
 * pread() based random-access
 */
PosixRandomAccessFile::PosixRandomAccessFile(const std::string& fname, int fd,
                                             const EnvOptions& options, std::shared_ptr<MyReadQueue>& ptr_rq)
    : filename_(fname),
      fd_(fd),
      use_direct_io_(options.use_direct_reads),
      logical_sector_size_(GetLogicalBufferSize(fd_)),
	  for_compaction_(false),
	  ptr_rq_(ptr_rq) {
  assert(!options.use_direct_reads || !options.use_mmap_reads);
  assert(!options.use_mmap_reads || sizeof(void*) < 8);

  //printf("[%s::%s::%d] filename { %s } for_compaction { %d } \n", __FILE__, __func__, __LINE__, filename_.c_str(), for_compaction_);

}

PosixRandomAccessFile::~PosixRandomAccessFile() { 
	//printf("[%s::%s::%d] filename { %s } for_compaction { %d }\n", __FILE__, __func__, __LINE__, filename_.c_str(), for_compaction_);
	if (for_compaction_) {
		ptr_rq_->RemoveFileFromReadQueue(filename_);
	    //printf("[%s::%s::%d] filename { %s } fd { %d } successfully removed\n", __FILE__, __func__, __LINE__, filename_.c_str(), fd_);

    }

	close(fd_); 
}

void PosixRandomAccessFile::SetForCompaction(bool for_compaction) {
	for_compaction_ = for_compaction;

	//printf("[%s::%s::%d] filename { %s } for_compaction %d\n", __FILE__, __func__, __LINE__, filename_.c_str(), for_compaction_);
	// TODO add to ReadQueue
	if (for_compaction_) {
		ptr_rq_->AddFileToReadQueue(filename_, fd_, use_direct_io_, GetRequiredBufferAlignment());
	}
}

Status PosixRandomAccessFile::Read_compaction(uint64_t offset, size_t n, Slice* result,
                                   char* scratch) const {
#ifdef DOPROFILE
	struct timespec local_time[2];
	clock_gettime(CLOCK_MONOTONIC, &local_time[0]);
#endif
	Status s = Read_compaction_internal(offset, n, result, scratch);
#ifdef DOPROFILE
	clock_gettime(CLOCK_MONOTONIC, &local_time[1]);
	calclock(local_time, &read_compaction_time, &read_compaction_count);
#endif
	
	return s;
}

Status PosixRandomAccessFile::Read_compaction_internal(uint64_t offset, size_t n, Slice* result,
                                   char* scratch) const {
	

  if (use_direct_io()) {
    assert(IsSectorAligned(offset, GetRequiredBufferAlignment()));
    assert(IsSectorAligned(n, GetRequiredBufferAlignment()));
    assert(IsSectorAligned(scratch, GetRequiredBufferAlignment()));
  }
	  

  // hkim
#if 1
  //printf("[%s::%s::%d] filename { %s } fd { %d } offset { %lu } size { %zu } \n", __FILE__, __func__, __LINE__, filename_.c_str(), fd_, offset, n);
  if (ptr_rq_->GetBufferCount() > 0) {
      ptr_rq_->GetData(filename_, fd_, offset, n, result, scratch);
      if (!result->empty()) {
          //printf("[%s::%s::%d] copy size { %zu } \n", __FILE__, __func__, __LINE__, result->size());
          return Status::OK();
      }
  } else {
      // should update offset of filename_
      ptr_rq_->UpdateFileOffset(filename_, (offset + n));
  }
#endif
  // hkim

  Status s;
  ssize_t r = -1;
  size_t left = n;
  char* ptr = scratch;
#if 0
  // hkim
  struct timespec local_time[2];
  //unsigned long long iotime = 0, iocount = 0;
  // hkim
#endif
  while (left > 0) {
#if 0
	  struct timespec tv[2];
	  clock_gettime(CLOCK_MONOTONIC, &tv[0]);
	  unsigned long long start_ts = tv[0].tv_sec*BILLION + tv[0].tv_nsec;
	  
	  printf("OP_PREAD_START %llu %s\n", start_ts, filename_.c_str());
#endif
#if 0
	  clock_gettime(CLOCK_MONOTONIC, &local_time[0]);
#endif
    r = pread(fd_, ptr, left, static_cast<off_t>(offset));
#if 0
	// hkim
	  clock_gettime(CLOCK_MONOTONIC, &local_time[1]);
	  calclock(local_time, &read_compaction_time, &read_compaction_count);
	//printf("thread %d filename %s OP_PREAD from %lu size %zu duration %llu \n", (int)pthread_self(), filename_.c_str(), offset, r, iotime);
	// hkim
#endif

#if 0
	clock_gettime(CLOCK_MONOTONIC, &tv[1]);
	unsigned long long end_ts = tv[1].tv_sec*BILLION + tv[1].tv_nsec;

	printf("OP_PREAD_END %llu %s %llu %lu %zu\n", end_ts, filename_.c_str(), (end_ts - start_ts), offset, r);
#endif

    if (r <= 0) {
      if (r == -1 && errno == EINTR) {
        continue;
      }
      break;
    }
    ptr += r;
    offset += r;
    left -= r;
    if (use_direct_io() &&
        r % static_cast<ssize_t>(GetRequiredBufferAlignment()) != 0) {
      // Bytes reads don't fill sectors. Should only happen at the end
      // of the file.
      break;
    }
  }
  if (r < 0) {
    // An error: return a non-ok status
    s = IOError(
        "While pread offset " + ToString(offset) + " len " + ToString(n),
        filename_, errno);
		printf("[%s::%s::%d] while pread offset %lu len %zu %s %d\n", __FILE__, __func__, __LINE__, offset, n, filename_.c_str(), errno);
  }
		
  //printf("[%s::%s::%d] filename { %s } offset { %lu } size { %ld }\n", __FILE__, __func__, __LINE__, filename_.c_str(), offset, r);

  *result = Slice(scratch, (r < 0) ? 0 : n - left);
  return s;
}

// still comes here for level1+
Status PosixRandomAccessFile::Read(uint64_t offset, size_t n, Slice* result,
                                   char* scratch) const {
	//printf("[%s::%s::%d] filename { %s } offset { %lu } size { %zu } \n", __FILE__, __func__, __LINE__, filename_.c_str(), offset, n);
  if (use_direct_io()) {
    assert(IsSectorAligned(offset, GetRequiredBufferAlignment()));
    assert(IsSectorAligned(n, GetRequiredBufferAlignment()));
    assert(IsSectorAligned(scratch, GetRequiredBufferAlignment()));
  }
  Status s;
  ssize_t r = -1;
  size_t left = n;
  char* ptr = scratch;
#if 0
  // hkim
  struct timespec local_time[2];
  unsigned long long iotime = 0, iocount = 0;
  // hkim
#endif
  while (left > 0) {
#if 0
	  struct timespec tv[2];
	  clock_gettime(CLOCK_MONOTONIC, &tv[0]);
	  unsigned long long start_ts = tv[0].tv_sec*BILLION + tv[0].tv_nsec;
	  
	  printf("[%s::%d] OP_PREAD_START %llu %s\n", __func__, __LINE__, start_ts, filename_.c_str());
#endif
#if 0
	  clock_gettime(CLOCK_MONOTONIC, &local_time[0]);
#endif
    r = pread(fd_, ptr, left, static_cast<off_t>(offset));
#if 0
	// hkim
	  clock_gettime(CLOCK_MONOTONIC, &local_time[1]);
	  calclock(local_time, &iotime, &iocount);
	printf("thread %d filename %s OP_PREAD from %lu size %zu duration %llu \n", (int)pthread_self(), filename_.c_str(), offset, r, iotime);
	// hkim
#endif

#if 0
	clock_gettime(CLOCK_MONOTONIC, &tv[1]);
	unsigned long long end_ts = tv[1].tv_sec*BILLION + tv[1].tv_nsec;

	printf("OP_PREAD_END %llu %s %llu %lu %zu\n", end_ts, filename_.c_str(), (end_ts - start_ts), offset, r);
#endif

    if (r <= 0) {
      if (r == -1 && errno == EINTR) {
        continue;
      }
      break;
    }
    ptr += r;
    offset += r;
    left -= r;
    if (use_direct_io() &&
        r % static_cast<ssize_t>(GetRequiredBufferAlignment()) != 0) {
      // Bytes reads don't fill sectors. Should only happen at the end
      // of the file.
      break;
    }
  }
  if (r < 0) {
    // An error: return a non-ok status
    s = IOError(
        "While pread offset " + ToString(offset) + " len " + ToString(n),
        filename_, errno);
  }
  *result = Slice(scratch, (r < 0) ? 0 : n - left);
  return s;
}

Status PosixRandomAccessFile::Prefetch(uint64_t offset, size_t n) {
  Status s;
  if (!use_direct_io()) {
    ssize_t r = 0;
#ifdef OS_LINUX
#if 0
	  struct timespec tv[2];
	  clock_gettime(CLOCK_MONOTONIC, &tv[0]);
	  unsigned long long start_ts = tv[0].tv_sec*BILLION + tv[0].tv_nsec;
	  
	  printf("OP_READAHEAD_START %llu %s\n", start_ts, filename_.c_str());
#endif

    r = readahead(fd_, offset, n);
#if 0
	clock_gettime(CLOCK_MONOTONIC, &tv[1]);
	unsigned long long end_ts = tv[1].tv_sec*BILLION + tv[1].tv_nsec;

	printf("OP_READAHEAD_END %llu %s %llu %lu %zu\n", end_ts, filename_.c_str(), (end_ts - start_ts), offset, r);
#endif
#endif
#ifdef OS_MACOSX
    radvisory advice;
    advice.ra_offset = static_cast<off_t>(offset);
    advice.ra_count = static_cast<int>(n);
    r = fcntl(fd_, F_RDADVISE, &advice);
#endif
    if (r == -1) {
      s = IOError("While prefetching offset " + ToString(offset) + " len " +
                      ToString(n),
                  filename_, errno);
    }
  }
  return s;
}

#if defined(OS_LINUX) || defined(OS_MACOSX) || defined(OS_AIX)
size_t PosixRandomAccessFile::GetUniqueId(char* id, size_t max_size) const {
  return PosixHelper::GetUniqueIdFromFile(fd_, id, max_size);
}
#endif

void PosixRandomAccessFile::Hint(AccessPattern pattern) {
  if (use_direct_io()) {
    return;
  }
  switch (pattern) {
    case NORMAL:
      Fadvise(fd_, 0, 0, POSIX_FADV_NORMAL);
      break;
    case RANDOM:
      Fadvise(fd_, 0, 0, POSIX_FADV_RANDOM);
      break;
    case SEQUENTIAL:
      Fadvise(fd_, 0, 0, POSIX_FADV_SEQUENTIAL);
      break;
    case WILLNEED:
      Fadvise(fd_, 0, 0, POSIX_FADV_WILLNEED);
      break;
    case DONTNEED:
      Fadvise(fd_, 0, 0, POSIX_FADV_DONTNEED);
      break;
    default:
      assert(false);
      break;
  }
}

Status PosixRandomAccessFile::InvalidateCache(size_t offset, size_t length) {
  if (use_direct_io()) {
    return Status::OK();
  }
#ifndef OS_LINUX
  return Status::OK();
#else
  // free OS pages
  int ret = Fadvise(fd_, offset, length, POSIX_FADV_DONTNEED);
  if (ret == 0) {
    return Status::OK();
  }
  return IOError("While fadvise NotNeeded offset " + ToString(offset) +
                     " len " + ToString(length),
                 filename_, errno);
#endif
}

/*
 * PosixMmapReadableFile
 *
 * mmap() based random-access
 */
// base[0,length-1] contains the mmapped contents of the file.
PosixMmapReadableFile::PosixMmapReadableFile(const int fd,
                                             const std::string& fname,
                                             void* base, size_t length,
                                             const EnvOptions& options)
    : fd_(fd), filename_(fname), mmapped_region_(base), length_(length) {
  fd_ = fd_ + 0;  // suppress the warning for used variables
  assert(options.use_mmap_reads);
  assert(!options.use_direct_reads);
}

PosixMmapReadableFile::~PosixMmapReadableFile() {
  int ret = munmap(mmapped_region_, length_);
  if (ret != 0) {
    fprintf(stdout, "failed to munmap %p length %" ROCKSDB_PRIszt " \n",
            mmapped_region_, length_);
  }
}

Status PosixMmapReadableFile::Read(uint64_t offset, size_t n, Slice* result,
                                   char* /*scratch*/) const {
  Status s;
  if (offset > length_) {
    *result = Slice();
    return IOError("While mmap read offset " + ToString(offset) +
                       " larger than file length " + ToString(length_),
                   filename_, EINVAL);
  } else if (offset + n > length_) {
    n = static_cast<size_t>(length_ - offset);
  }
  *result = Slice(reinterpret_cast<char*>(mmapped_region_) + offset, n);
  return s;
}

Status PosixMmapReadableFile::InvalidateCache(size_t offset, size_t length) {
#ifndef OS_LINUX
  return Status::OK();
#else
  // free OS pages
  int ret = Fadvise(fd_, offset, length, POSIX_FADV_DONTNEED);
  if (ret == 0) {
    return Status::OK();
  }
  return IOError("While fadvise not needed. Offset " + ToString(offset) +
                     " len" + ToString(length),
                 filename_, errno);
#endif
}

/*
 * PosixMmapFile
 *
 * We preallocate up to an extra megabyte and use memcpy to append new
 * data to the file.  This is safe since we either properly close the
 * file before reading from it, or for log files, the reading code
 * knows enough to skip zero suffixes.
 */
Status PosixMmapFile::UnmapCurrentRegion() {
  TEST_KILL_RANDOM("PosixMmapFile::UnmapCurrentRegion:0", rocksdb_kill_odds);
  if (base_ != nullptr) {
    int munmap_status = munmap(base_, limit_ - base_);
    if (munmap_status != 0) {
      return IOError("While munmap", filename_, munmap_status);
    }
    file_offset_ += limit_ - base_;
    base_ = nullptr;
    limit_ = nullptr;
    last_sync_ = nullptr;
    dst_ = nullptr;

    // Increase the amount we map the next time, but capped at 1MB
    if (map_size_ < (1 << 20)) {
      map_size_ *= 2;
    }
  }
  return Status::OK();
}

Status PosixMmapFile::MapNewRegion() {
#ifdef ROCKSDB_FALLOCATE_PRESENT
  assert(base_ == nullptr);
  TEST_KILL_RANDOM("PosixMmapFile::UnmapCurrentRegion:0", rocksdb_kill_odds);
  // we can't fallocate with FALLOC_FL_KEEP_SIZE here
  if (allow_fallocate_) {
    IOSTATS_TIMER_GUARD(allocate_nanos);
    int alloc_status = fallocate(fd_, 0, file_offset_, map_size_);
    if (alloc_status != 0) {
      // fallback to posix_fallocate
      alloc_status = posix_fallocate(fd_, file_offset_, map_size_);
    }
    if (alloc_status != 0) {
      return Status::IOError("Error allocating space to file : " + filename_ +
                             "Error : " + strerror(alloc_status));
    }
  }

  TEST_KILL_RANDOM("PosixMmapFile::Append:1", rocksdb_kill_odds);
  void* ptr = mmap(nullptr, map_size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_,
                   file_offset_);
  if (ptr == MAP_FAILED) {
    return Status::IOError("MMap failed on " + filename_);
  }
  TEST_KILL_RANDOM("PosixMmapFile::Append:2", rocksdb_kill_odds);

  base_ = reinterpret_cast<char*>(ptr);
  limit_ = base_ + map_size_;
  dst_ = base_;
  last_sync_ = base_;
  return Status::OK();
#else
  return Status::NotSupported("This platform doesn't support fallocate()");
#endif
}

Status PosixMmapFile::Msync() {
  if (dst_ == last_sync_) {
    return Status::OK();
  }
  // Find the beginnings of the pages that contain the first and last
  // bytes to be synced.
  size_t p1 = TruncateToPageBoundary(last_sync_ - base_);
  size_t p2 = TruncateToPageBoundary(dst_ - base_ - 1);
  last_sync_ = dst_;
  TEST_KILL_RANDOM("PosixMmapFile::Msync:0", rocksdb_kill_odds);
  if (msync(base_ + p1, p2 - p1 + page_size_, MS_SYNC) < 0) {
    return IOError("While msync", filename_, errno);
  }
  return Status::OK();
}

PosixMmapFile::PosixMmapFile(const std::string& fname, int fd, size_t page_size,
                             const EnvOptions& options)
    : filename_(fname),
      fd_(fd),
      page_size_(page_size),
      map_size_(Roundup(65536, page_size)),
      base_(nullptr),
      limit_(nullptr),
      dst_(nullptr),
      last_sync_(nullptr),
      file_offset_(0) {
#ifdef ROCKSDB_FALLOCATE_PRESENT
  allow_fallocate_ = options.allow_fallocate;
  fallocate_with_keep_size_ = options.fallocate_with_keep_size;
#endif
  assert((page_size & (page_size - 1)) == 0);
  assert(options.use_mmap_writes);
  assert(!options.use_direct_writes);
}

PosixMmapFile::~PosixMmapFile() {
  if (fd_ >= 0) {
    PosixMmapFile::Close();
  }
}

Status PosixMmapFile::Append(const Slice& data) {
  const char* src = data.data();
  size_t left = data.size();
  while (left > 0) {
    assert(base_ <= dst_);
    assert(dst_ <= limit_);
    size_t avail = limit_ - dst_;
    if (avail == 0) {
      Status s = UnmapCurrentRegion();
      if (!s.ok()) {
        return s;
      }
      s = MapNewRegion();
      if (!s.ok()) {
        return s;
      }
      TEST_KILL_RANDOM("PosixMmapFile::Append:0", rocksdb_kill_odds);
    }

    size_t n = (left <= avail) ? left : avail;
    assert(dst_);
    memcpy(dst_, src, n);
    dst_ += n;
    src += n;
    left -= n;
  }
  return Status::OK();
}

Status PosixMmapFile::Close() {
  Status s;
  size_t unused = limit_ - dst_;

  s = UnmapCurrentRegion();
  if (!s.ok()) {
    s = IOError("While closing mmapped file", filename_, errno);
  } else if (unused > 0) {
    // Trim the extra space at the end of the file
    if (ftruncate(fd_, file_offset_ - unused) < 0) {
      s = IOError("While ftruncating mmaped file", filename_, errno);
    }
  }

  if (close(fd_) < 0) {
    if (s.ok()) {
      s = IOError("While closing mmapped file", filename_, errno);
    }
  }

  fd_ = -1;
  base_ = nullptr;
  limit_ = nullptr;
  return s;
}

Status PosixMmapFile::Flush() { return Status::OK(); }

Status PosixMmapFile::Sync() {
  if (fdatasync(fd_) < 0) {
    return IOError("While fdatasync mmapped file", filename_, errno);
  }

  return Msync();
}

/**
 * Flush data as well as metadata to stable storage.
 */
Status PosixMmapFile::Fsync() {
  if (fsync(fd_) < 0) {
    return IOError("While fsync mmaped file", filename_, errno);
  }

  return Msync();
}

/**
 * Get the size of valid data in the file. This will not match the
 * size that is returned from the filesystem because we use mmap
 * to extend file by map_size every time.
 */
uint64_t PosixMmapFile::GetFileSize() {
  size_t used = dst_ - base_;
  return file_offset_ + used;
}

Status PosixMmapFile::InvalidateCache(size_t offset, size_t length) {
#ifndef OS_LINUX
  return Status::OK();
#else
  // free OS pages
  int ret = Fadvise(fd_, offset, length, POSIX_FADV_DONTNEED);
  if (ret == 0) {
    return Status::OK();
  }
  return IOError("While fadvise NotNeeded mmapped file", filename_, errno);
#endif
}

#ifdef ROCKSDB_FALLOCATE_PRESENT
Status PosixMmapFile::Allocate(uint64_t offset, uint64_t len) {
  assert(offset <= std::numeric_limits<off_t>::max());
  assert(len <= std::numeric_limits<off_t>::max());
  TEST_KILL_RANDOM("PosixMmapFile::Allocate:0", rocksdb_kill_odds);
  int alloc_status = 0;
  if (allow_fallocate_) {
    alloc_status = fallocate(
        fd_, fallocate_with_keep_size_ ? FALLOC_FL_KEEP_SIZE : 0,
          static_cast<off_t>(offset), static_cast<off_t>(len));
  }
  if (alloc_status == 0) {
    return Status::OK();
  } else {
    return IOError(
        "While fallocate offset " + ToString(offset) + " len " + ToString(len),
        filename_, errno);
  }
}
#endif

/*
 * PosixWritableFile
 *
 * Use posix write to write data to a file.
 */
#if 1
PosixWritableFile::PosixWritableFile(const std::string& fname, int fd,
                                     const EnvOptions& options, std::shared_ptr<MyWriteQueue>& ptr_wq)
    : filename_(fname),
      use_direct_io_(options.use_direct_writes),
      fd_(fd),
      filesize_(0),
      logical_sector_size_(GetLogicalBufferSize(fd_)),
	  ptr_wq_(ptr_wq) {
#ifdef ROCKSDB_FALLOCATE_PRESENT
  allow_fallocate_ = options.allow_fallocate;
  fallocate_with_keep_size_ = options.fallocate_with_keep_size;
#endif
  assert(!options.use_mmap_writes);

#if 0
  // hkim
  if (filename_.find(".sst") != std::string::npos) {
	  ptr_wq_->AddFileToWriteQueue(fname, fd, options.use_direct_writes, GetRequiredBufferAlignment());
  }
#endif
	
}
#endif

#if 0
PosixWritableFile::PosixWritableFile(const std::string& fname, int fd,
                                     const EnvOptions& options)
    : filename_(fname),
      use_direct_io_(options.use_direct_writes),
      fd_(fd),
      logical_sector_size_(GetLogicalBufferSize(fd_)) {
#ifdef ROCKSDB_FALLOCATE_PRESENT
  allow_fallocate_ = options.allow_fallocate;
  fallocate_with_keep_size_ = options.fallocate_with_keep_size;
#endif
  assert(!options.use_mmap_writes);
  // hkim
  filesize_ = 0;
  local_offset = 0;
}
#endif

PosixWritableFile::~PosixWritableFile() {
	//printf("[%s::%s::%d] filename { %s }  fd_ { %d }\n", __FILE__, __func__, __LINE__, filename_.c_str(), fd_);
	// hkim
	if (filename_.find(".sst") != std::string::npos)
		ptr_wq_->RemoveFileFromWriteQueue(filename_);

	if (fd_ >= 0) {
		PosixWritableFile::Close();
	}
}

#if 0
Status PosixWritableFile::Append(const Slice& data) {
  if (use_direct_io()) {
    assert(IsSectorAligned(data.size(), GetRequiredBufferAlignment()));
    assert(IsSectorAligned(data.data(), GetRequiredBufferAlignment()));
  }

  if (filename_.find("sst", 0, 3) != std::string::npos) {
	  filesize_ += data.size();

	  struct thread_args args;
	  args.pFile = this;
	  args.src = data.data();
	  args.size = data.size();

	  pthread_t write_thread_;
	  pthread_create(&write_thread_, NULL, ThreadWrapper, (void *)&args);
  } else {
	  return Append_original(data);
  }

  return Status::OK();
}
#endif

#if 0
Status PosixWritableFile::Append(const Slice& data) {
  if (use_direct_io()) {
    assert(IsSectorAligned(data.size(), GetRequiredBufferAlignment()));
    assert(IsSectorAligned(data.data(), GetRequiredBufferAlignment()));
  }

  filesize_ += data.size();

  struct thread_args args;
  args.pFile = this;
  args.src = data.data();
  args.size = data.size();

  pthread_t write_thread_;
  pthread_create(&write_thread_, NULL, ThreadWrapper, (void *)&args);

  return Status::OK();
}
#endif

Status PosixWritableFile::Append(const Slice& data) {
  if (use_direct_io()) {
    assert(IsSectorAligned(data.size(), GetRequiredBufferAlignment()));
    assert(IsSectorAligned(data.data(), GetRequiredBufferAlignment()));
  }
  const char* src = data.data();
  size_t left = data.size();
#if 0
  // hkim
  struct timespec local_time[2];
  unsigned long long iotime = 0, iocount = 0;
  // hkim
#endif
  while (left != 0) {
#if 0
	  clock_gettime(CLOCK_MONOTONIC, &local_time[0]);
#endif
#if 0
	  struct timespec tv[2];
	  clock_gettime(CLOCK_MONOTONIC, &tv[0]);
	  unsigned long long start_ts = tv[0].tv_sec*BILLION + tv[0].tv_nsec;

	  if (filename_.find("sst", 0, 3) != std::string::npos) {
		  printf("OP_WRITE_START %llu %s\n", start_ts, filename_.c_str());
	  }
#endif

    ssize_t done = write(fd_, src, left);
#if 0
	clock_gettime(CLOCK_MONOTONIC, &tv[1]);
	unsigned long long end_ts = tv[1].tv_sec*BILLION + tv[1].tv_nsec;

	if (filename_.find("sst", 0, 3) != std::string::npos) {
		printf("OP_WRITE_END %llu %s %llu %zu \n", end_ts, filename_.c_str(), (end_ts - start_ts), done);
	}
#endif
#if 0
	// hkim
	  clock_gettime(CLOCK_MONOTONIC, &local_time[1]);
	  calclock(local_time, &iotime, &iocount);
	  printf("thread %d filename %s OP_WRITE %zu bytes duration %llu \n", (int)pthread_self(), filename_.c_str(), done, iotime);
	// hkim
#endif
    if (done < 0) {
      if (errno == EINTR) {
        continue;
      }
      return IOError("While appending to file", filename_, errno);
    }
    left -= done;
    src += done;
  }
  filesize_ += data.size();
  return Status::OK();
}

#if 0
Status PosixWritableFile::PositionedAppend_original(const Slice& data, uint64_t offset) {
  if (use_direct_io()) {
    assert(IsSectorAligned(offset, GetRequiredBufferAlignment()));
    assert(IsSectorAligned(data.size(), GetRequiredBufferAlignment()));
    assert(IsSectorAligned(data.data(), GetRequiredBufferAlignment()));
  }
  assert(offset <= std::numeric_limits<off_t>::max());
  const char* src = data.data();
  size_t left = data.size();
#if 0
  // hkim
  struct timespec local_time[2];
  unsigned long long iotime = 0, iocount = 0;
  // hkim
#endif
  while (left != 0) {
#if 0
	  struct timespec tv[2];
	  clock_gettime(CLOCK_MONOTONIC, &tv[0]);
	  unsigned long long start_ts = tv[0].tv_sec*BILLION + tv[0].tv_nsec;
	  
	  printf("OP_PWRITE_START %llu %s\n", start_ts, filename_.c_str());
#endif
#if 0
	  clock_gettime(CLOCK_MONOTONIC, &local_time[0]);
#endif

    ssize_t done = pwrite(fd_, src, left, static_cast<off_t>(offset));
#if 0
	// hkim
	  clock_gettime(CLOCK_MONOTONIC, &local_time[1]);
	  calclock(local_time, &iotime, &iocount);
	  printf("thread %d filename %s OP_PWRITE from %lu size %zu duration %llu\n", (int)pthread_self(), filename_.c_str(), offset, done, iotime);
	// hkim
#endif

#if 0
	clock_gettime(CLOCK_MONOTONIC, &tv[1]);
	unsigned long long end_ts = tv[1].tv_sec*BILLION + tv[1].tv_nsec;

	printf("OP_PWRITE_END %llu %s %llu %lu %zu\n", end_ts, filename_.c_str(), (end_ts - start_ts), offset, done);
#endif

    if (done < 0) {
      if (errno == EINTR) {
        continue;
      }
      return IOError("While pwrite to file at offset " + ToString(offset),
                     filename_, errno);
    }
    left -= done;
    offset += done;
    src += done;
  }
  filesize_ = offset;
  return Status::OK();
}
#endif

#if 1
Status PosixWritableFile::PositionedAppend_compaction(const Slice& data, uint64_t offset) {
  if (use_direct_io()) {
    assert(IsSectorAligned(offset, GetRequiredBufferAlignment()));
    assert(IsSectorAligned(data.size(), GetRequiredBufferAlignment()));
    assert(IsSectorAligned(data.data(), GetRequiredBufferAlignment()));
  }
  assert(offset <= std::numeric_limits<off_t>::max());
  const char* src = data.data();
  size_t left = data.size();
#if DOPROFILE
  // hkim
  struct timespec local_time[2];
  //unsigned long long iotime = 0, iocount = 0;
  // hkim
#endif
  while (left != 0) {
#if 0
	  struct timespec tv[2];
	  clock_gettime(CLOCK_MONOTONIC, &tv[0]);
	  unsigned long long start_ts = tv[0].tv_sec*BILLION + tv[0].tv_nsec;
	  
	  printf("OP_PWRITE_START %llu %s\n", start_ts, filename_.c_str());
#endif
#ifdef DOPROFILE
	  clock_gettime(CLOCK_MONOTONIC, &local_time[0]);
#endif

    ssize_t done = pwrite(fd_, src, left, static_cast<off_t>(offset));
#ifdef DOPROFILE
	// hkim
	  clock_gettime(CLOCK_MONOTONIC, &local_time[1]);
	  calclock(local_time, &append_compaction_time, &append_compaction_count);
	  //printf("thread %d filename %s OP_PWRITE from %lu size %zu duration %llu\n", (int)pthread_self(), filename_.c_str(), offset, done, iotime);
	// hkim
#endif

#if 0
	clock_gettime(CLOCK_MONOTONIC, &tv[1]);
	unsigned long long end_ts = tv[1].tv_sec*BILLION + tv[1].tv_nsec;

	printf("OP_PWRITE_END %llu %s %llu %lu %zu\n", end_ts, filename_.c_str(), (end_ts - start_ts), offset, done);
#endif

    if (done < 0) {
      if (errno == EINTR) {
        continue;
      }
      return IOError("While pwrite to file at offset " + ToString(offset),
                     filename_, errno);
    }
    left -= done;
    offset += done;
    src += done;
  }
  filesize_ = offset;
  return Status::OK();
}

Status PosixWritableFile::PositionedAppend(const Slice& data, uint64_t offset) {
  if (use_direct_io()) {
    assert(IsSectorAligned(offset, GetRequiredBufferAlignment()));
    assert(IsSectorAligned(data.size(), GetRequiredBufferAlignment()));
    assert(IsSectorAligned(data.data(), GetRequiredBufferAlignment()));
  }
  assert(offset <= std::numeric_limits<off_t>::max());
  const char* src = data.data();
  size_t left = data.size();
#if 0
  // hkim
  struct timespec local_time[2];
  unsigned long long iotime = 0, iocount = 0;
  // hkim
#endif
  while (left != 0) {
#if 0
	  struct timespec tv[2];
	  clock_gettime(CLOCK_MONOTONIC, &tv[0]);
	  unsigned long long start_ts = tv[0].tv_sec*BILLION + tv[0].tv_nsec;
	  
	  printf("OP_PWRITE_START %llu %s\n", start_ts, filename_.c_str());
#endif
#if 0
	  clock_gettime(CLOCK_MONOTONIC, &local_time[0]);
#endif

    ssize_t done = pwrite(fd_, src, left, static_cast<off_t>(offset));
#if 0
	// hkim
	  clock_gettime(CLOCK_MONOTONIC, &local_time[1]);
	  calclock(local_time, &iotime, &iocount);
	  printf("thread %d filename %s OP_PWRITE from %lu size %zu duration %llu\n", (int)pthread_self(), filename_.c_str(), offset, done, iotime);
	// hkim
#endif

#if 0
	clock_gettime(CLOCK_MONOTONIC, &tv[1]);
	unsigned long long end_ts = tv[1].tv_sec*BILLION + tv[1].tv_nsec;

	printf("OP_PWRITE_END %llu %s %llu %lu %zu\n", end_ts, filename_.c_str(), (end_ts - start_ts), offset, done);
#endif

    if (done < 0) {
      if (errno == EINTR) {
        continue;
      }
      return IOError("While pwrite to file at offset " + ToString(offset),
                     filename_, errno);
    }
    left -= done;
    offset += done;
    src += done;
  }
  filesize_ = offset;
  return Status::OK();
}
#endif

Status PosixWritableFile::Truncate(uint64_t size) {
  Status s;
  int r = ftruncate(fd_, size);
  if (r < 0) {
    s = IOError("While ftruncate file to size " + ToString(size), filename_,
                errno);
  } else {
    filesize_ = size;
  }
  return s;
}

Status PosixWritableFile::Close() {
  Status s;

  size_t block_size;
  size_t last_allocated_block;
  GetPreallocationStatus(&block_size, &last_allocated_block);
  if (last_allocated_block > 0) {
    // trim the extra space preallocated at the end of the file
    // NOTE(ljin): we probably don't want to surface failure as an IOError,
    // but it will be nice to log these errors.
    int dummy __attribute__((__unused__));
    dummy = ftruncate(fd_, filesize_);
#if defined(ROCKSDB_FALLOCATE_PRESENT) && !defined(TRAVIS)
    // in some file systems, ftruncate only trims trailing space if the
    // new file size is smaller than the current size. Calling fallocate
    // with FALLOC_FL_PUNCH_HOLE flag to explicitly release these unused
    // blocks. FALLOC_FL_PUNCH_HOLE is supported on at least the following
    // filesystems:
    //   XFS (since Linux 2.6.38)
    //   ext4 (since Linux 3.0)
    //   Btrfs (since Linux 3.7)
    //   tmpfs (since Linux 3.5)
    // We ignore error since failure of this operation does not affect
    // correctness.
    // TRAVIS - this code does not work on TRAVIS filesystems.
    // the FALLOC_FL_KEEP_SIZE option is expected to not change the size
    // of the file, but it does. Simple strace report will show that.
    // While we work with Travis-CI team to figure out if this is a
    // quirk of Docker/AUFS, we will comment this out.
    struct stat file_stats;
    int result = fstat(fd_, &file_stats);
    // After ftruncate, we check whether ftruncate has the correct behavior.
    // If not, we should hack it with FALLOC_FL_PUNCH_HOLE
    if (result == 0 &&
        (file_stats.st_size + file_stats.st_blksize - 1) /
            file_stats.st_blksize !=
        file_stats.st_blocks / (file_stats.st_blksize / 512)) {
      IOSTATS_TIMER_GUARD(allocate_nanos);
      if (allow_fallocate_) {
        fallocate(fd_, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, filesize_,
                  block_size * last_allocated_block - filesize_);
      }
    }
#endif
  }

  if (close(fd_) < 0) {
    s = IOError("While closing file after writing", filename_, errno);
  }
  fd_ = -1;
  return s;
}

// write out the cached data to the OS cache
Status PosixWritableFile::Flush() { 
		// hkim
		//printf("[%s::%s::%d] \n", __FILE__, __func__, __LINE__);
	return Status::OK(); 
}

Status PosixWritableFile::Sync() {
  if (fdatasync(fd_) < 0) {
    return IOError("While fdatasync", filename_, errno);
  }
  return Status::OK();
}

Status PosixWritableFile::Fsync() {
  if (fsync(fd_) < 0) {
    return IOError("While fsync", filename_, errno);
  }
  return Status::OK();
}

bool PosixWritableFile::IsSyncThreadSafe() const { return true; }

uint64_t PosixWritableFile::GetFileSize() { return filesize_; }

void PosixWritableFile::SetWriteLifeTimeHint(Env::WriteLifeTimeHint hint) {
#ifdef OS_LINUX
// Suppress Valgrind "Unimplemented functionality" error.
#ifndef ROCKSDB_VALGRIND_RUN
  if (hint == write_hint_) {
    return;
  }
  if (fcntl(fd_, F_SET_RW_HINT, &hint) == 0) {
    write_hint_ = hint;
  }
#else
  (void)hint;
#endif // ROCKSDB_VALGRIND_RUN
#else
  (void)hint;
#endif // OS_LINUX
}

Status PosixWritableFile::InvalidateCache(size_t offset, size_t length) {
  if (use_direct_io()) {
    return Status::OK();
  }
#ifndef OS_LINUX
  return Status::OK();
#else
  // free OS pages
  int ret = Fadvise(fd_, offset, length, POSIX_FADV_DONTNEED);
  if (ret == 0) {
    return Status::OK();
  }
  return IOError("While fadvise NotNeeded", filename_, errno);
#endif
}

#ifdef ROCKSDB_FALLOCATE_PRESENT
Status PosixWritableFile::Allocate(uint64_t offset, uint64_t len) {
  assert(offset <= std::numeric_limits<off_t>::max());
  assert(len <= std::numeric_limits<off_t>::max());
  TEST_KILL_RANDOM("PosixWritableFile::Allocate:0", rocksdb_kill_odds);
  IOSTATS_TIMER_GUARD(allocate_nanos);
  int alloc_status = 0;
  if (allow_fallocate_) {
    alloc_status = fallocate(
        fd_, fallocate_with_keep_size_ ? FALLOC_FL_KEEP_SIZE : 0,
        static_cast<off_t>(offset), static_cast<off_t>(len));
  }
  if (alloc_status == 0) {
    return Status::OK();
  } else {
    return IOError(
        "While fallocate offset " + ToString(offset) + " len " + ToString(len),
        filename_, errno);
  }
}
#endif

#ifdef ROCKSDB_RANGESYNC_PRESENT
Status PosixWritableFile::RangeSync(uint64_t offset, uint64_t nbytes) {
  assert(offset <= std::numeric_limits<off_t>::max());
  assert(nbytes <= std::numeric_limits<off_t>::max());
  if (sync_file_range(fd_, static_cast<off_t>(offset),
      static_cast<off_t>(nbytes), SYNC_FILE_RANGE_WRITE) == 0) {
    return Status::OK();
  } else {
    return IOError("While sync_file_range offset " + ToString(offset) +
                       " bytes " + ToString(nbytes),
                   filename_, errno);
  }
}
#endif

#ifdef OS_LINUX
size_t PosixWritableFile::GetUniqueId(char* id, size_t max_size) const {
  return PosixHelper::GetUniqueIdFromFile(fd_, id, max_size);
}
#endif

/*
 * PosixRandomRWFile
 */

PosixRandomRWFile::PosixRandomRWFile(const std::string& fname, int fd,
                                     const EnvOptions& /*options*/)
    : filename_(fname), fd_(fd) {}

PosixRandomRWFile::~PosixRandomRWFile() {
  if (fd_ >= 0) {
    Close();
  }
}

Status PosixRandomRWFile::Write(uint64_t offset, const Slice& data) {
  const char* src = data.data();
  size_t left = data.size();
#if 0
  // hkim
  struct timespec local_time[2];
  unsigned long long iotime = 0, iocount = 0;
  // hkim
#endif
  while (left != 0) {
#if 0
	  struct timespec tv[2];
	  clock_gettime(CLOCK_MONOTONIC, &tv[0]);
	  unsigned long long start_ts = tv[0].tv_sec*BILLION + tv[0].tv_nsec;
	  
	  printf("OP_PWRITE_START %llu %s\n", start_ts, filename_.c_str());
#endif

#if 0
	  clock_gettime(CLOCK_MONOTONIC, &local_time[0]);
#endif
    ssize_t done = pwrite(fd_, src, left, offset);
#if 0
	// hkim
	  clock_gettime(CLOCK_MONOTONIC, &local_time[1]);
	  calclock(local_time, &iotime, &iocount);
	  printf("thread %d filename %s OP_PWRITE from %lu size %zu duration %llu\n", (int)pthread_self(), filename_.c_str(), offset, done, iotime);
	// hkim
#endif

#if 0
	clock_gettime(CLOCK_MONOTONIC, &tv[1]);
	unsigned long long end_ts = tv[1].tv_sec*BILLION + tv[1].tv_nsec;

	printf("OP_PWRITE_END %llu %s %llu %lu %zu\n", end_ts, filename_.c_str(), (end_ts - start_ts), offset, done);
#endif

    if (done < 0) {
      // error while writing to file
      if (errno == EINTR) {
        // write was interrupted, try again.
        continue;
      }
      return IOError(
          "While write random read/write file at offset " + ToString(offset),
          filename_, errno);
    }

    // Wrote `done` bytes
    left -= done;
    offset += done;
    src += done;
  }

  return Status::OK();
}

Status PosixRandomRWFile::Read(uint64_t offset, size_t n, Slice* result,
                               char* scratch) const {
  size_t left = n;
  char* ptr = scratch;
#if 0
  // hkim
  struct timespec local_time[2];
  unsigned long long iotime = 0, iocount = 0;
  // hkim
#endif
  while (left > 0) {
#if 0
	  struct timespec tv[2];
	  clock_gettime(CLOCK_MONOTONIC, &tv[0]);
	  unsigned long long start_ts = tv[0].tv_sec*BILLION + tv[0].tv_nsec;
	  
	  printf("OP_PREAD_START %llu %s\n", start_ts, filename_.c_str());
#endif

#if 0
	  clock_gettime(CLOCK_MONOTONIC, &local_time[0]);
#endif
    ssize_t done = pread(fd_, ptr, left, offset);
#if 0
	// hkim
	  clock_gettime(CLOCK_MONOTONIC, &local_time[1]);
	  calclock(local_time, &iotime, &iocount);
	  printf("thread %d filename %s OP_PREAD from %lu size %zu duration %llu\n", (int)pthread_self(), filename_.c_str(), offset, done, iotime);
	// hkim
#endif

#if 0
	clock_gettime(CLOCK_MONOTONIC, &tv[1]);
	unsigned long long end_ts = tv[1].tv_sec*BILLION + tv[1].tv_nsec;

	printf("OP_PREAD_END %llu %s %llu %lu %zu\n", end_ts, filename_.c_str(), (end_ts - start_ts), offset, done);
#endif

    if (done < 0) {
      // error while reading from file
      if (errno == EINTR) {
        // read was interrupted, try again.
        continue;
      }
      return IOError("While reading random read/write file offset " +
                         ToString(offset) + " len " + ToString(n),
                     filename_, errno);
    } else if (done == 0) {
      // Nothing more to read
      break;
    }

    // Read `done` bytes
    ptr += done;
    offset += done;
    left -= done;
  }

  *result = Slice(scratch, n - left);
  return Status::OK();
}

Status PosixRandomRWFile::Flush() { return Status::OK(); }

Status PosixRandomRWFile::Sync() {
  if (fdatasync(fd_) < 0) {
    return IOError("While fdatasync random read/write file", filename_, errno);
  }
  return Status::OK();
}

Status PosixRandomRWFile::Fsync() {
  if (fsync(fd_) < 0) {
    return IOError("While fsync random read/write file", filename_, errno);
  }
  return Status::OK();
}

Status PosixRandomRWFile::Close() {
  if (close(fd_) < 0) {
    return IOError("While close random read/write file", filename_, errno);
  }
  fd_ = -1;
  return Status::OK();
}

/*
 * PosixDirectory
 */

PosixDirectory::~PosixDirectory() { close(fd_); }

Status PosixDirectory::Fsync() {
#ifndef OS_AIX
  if (fsync(fd_) == -1) {
    return IOError("While fsync", "a directory", errno);
  }
#endif
  return Status::OK();
}
}  // namespace rocksdb
#endif
