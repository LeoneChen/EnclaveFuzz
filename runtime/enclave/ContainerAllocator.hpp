/*
 * Code is based on follow copyright
 * =======================================================
 * The following code example is taken from the book
 * "The C++ Standard Library - A Tutorial and Reference"
 * by Nicolai M. Josuttis, Addison-Wesley, 1999
 *
 * (C) Copyright Nicolai M. Josuttis 1999.
 * Permission to copy, use, modify, sell and distribute this software
 * is granted provided this copyright notice appears in all copies.
 * This software is provided "as is" without express or implied
 * warranty, and with no claim as to its suitability for any purpose.
 */

#ifndef CONTAINER_ALLOCATOR_HPP
#define CONTAINER_ALLOCATOR_HPP

#include "InternalDlmalloc.hpp"
#include "Malloc.hpp"
#include <stddef.h>
#include <stdlib.h>

namespace SGXSan {
template <class T> class ContainerAllocator {
public:
  // type definitions
  typedef T value_type;
  typedef T *pointer;
  typedef const T *const_pointer;
  typedef T &reference;
  typedef const T &const_reference;
  typedef size_t size_type;
  typedef ptrdiff_t difference_type;

  // rebind allocator to type U
  template <class U> struct rebind { typedef ContainerAllocator<U> other; };

  // return address of values
  pointer address(reference value) const { return &value; }
  const_pointer address(const_reference value) const { return &value; }

  /* constructors and destructor
   * - nothing to do because the allocator has no state
   */
  ContainerAllocator() noexcept {}
  ContainerAllocator(const ContainerAllocator &) noexcept {}
  template <class U>
  ContainerAllocator(const ContainerAllocator<U> &) noexcept {}
  ~ContainerAllocator() noexcept {}

  // return maximum number of elements that can be allocated
  size_type max_size() const noexcept { return size_type(~0) / sizeof(T); }

  // allocate but don't initialize num elements of type T
  pointer allocate(size_type num, const void * = 0) {
    if (num > max_size())
      abort();

    // replace malloc with dlmalloc, as we modified malloc which may call here
    pointer ret = (pointer)(dlmalloc(num * sizeof(T)));
    update_heap_usage(ret, dlmalloc_usable_size);
    int try_times = 3;
    while (ret == nullptr) {
      if (try_times-- == 0)
        abort();
      ret = (pointer)dlmalloc(num * sizeof(T));
      update_heap_usage(ret, dlmalloc_usable_size);
    }

    return ret;
  }

  // initialize elements of allocated storage p with value value
  void construct(pointer p, const T &value) {
    // initialize memory with placement new
    new ((void *)p) T(value);
  }

  // destroy elements of initialized storage p
  void destroy(pointer p) {
    // destroy objects by calling their destructor
    p->~T();
  }

  // deallocate storage p of deleted elements
  void deallocate(pointer p, size_type num) {
    (void)num;
    if (p) {
      update_heap_usage((void *)p, dlmalloc_usable_size, false);
      dlfree((void *)p);
    }
  }
};

// return that all specializations of this allocator are interchangeable
template <class T1, class T2>
bool operator==(const ContainerAllocator<T1> &,
                const ContainerAllocator<T2> &) throw() {
  return true;
}
template <class T1, class T2>
bool operator!=(const ContainerAllocator<T1> &,
                const ContainerAllocator<T2> &) throw() {
  return false;
}
} // namespace SGXSan

#endif