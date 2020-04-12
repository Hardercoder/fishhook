// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name Facebook nor the names of its contributors may be used to
//     endorse or promote products derived from this software without specific
//     prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "fishhook.h"

#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif

//为了将多次绑定时的多个符号组织成一个链式结构，fishhook 自定义了一个链表结构来组织这个逻辑，其中的每个节点数据结构
struct rebindings_entry {
    struct rebinding *rebindings; // rebinding 数组实例
    size_t rebindings_nel;// 元素数量
    struct rebindings_entry *next; // 链表索引
};
// 全局量，直接拿出表头
static struct rebindings_entry *_rebindings_head;
/** * prepend_rebindings 用于 rebindings_entry 结构的维护 *
 struct rebindings_entry **rebindings_head - 对应的是 static 的 _rebindings_head *
 struct rebinding rebindings[] - 传入的方法符号数组 *
 size_t nel - 数组对应的元素数量 */
static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel) {
    // 声明 rebindings_entry 一个指针，并为其分配空间
    struct rebindings_entry *new_entry = (struct rebindings_entry *) malloc(sizeof(struct rebindings_entry));
    // 分配空间失败的容错处理
    if (!new_entry) {
        return -1;
    }
    // 为链表中元素的 rebindings 实例分配指定空间
    new_entry->rebindings = (struct rebinding *) malloc(sizeof(struct rebinding) * nel);
    // 分配空间失败的容错处理
    if (!new_entry->rebindings) {
        free(new_entry);
        return -1;
    }
    // 将 rebindings 数组中 copy 到 new_entry -> rebingdings 成员中
    memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
    // 为 new_entry -> rebindings_nel 赋值
    new_entry->rebindings_nel = nel;
    // 头插法维护链表结构
    // 为 new_entry -> newx 赋值，维护链表结构
    new_entry->next = *rebindings_head;
    // 移动 head 指针，指向表头
    *rebindings_head = new_entry;
    return 0;
}

static vm_prot_t get_protection(void *sectionStart) {
    mach_port_t task = mach_task_self();
    vm_size_t size = 0;
    vm_address_t address = (vm_address_t)sectionStart;
    memory_object_name_t object;
#if __LP64__
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    vm_region_basic_info_data_64_t info;
    kern_return_t info_ret = vm_region_64(
                                          task, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_64_t)&info, &count, &object);
#else
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT;
    vm_region_basic_info_data_t info;
    kern_return_t info_ret = vm_region(task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &count, &object);
#endif
    if (info_ret == KERN_SUCCESS) {
        return info.protection;
    } else {
        return VM_PROT_READ;
    }
}
/*
 描述了替换 __DATA.__la_symbol_ptr 和 __DATA.__la_symbol_ptr 的 Indirect Pointer 主要过程。
 从 reserved1 字段获取到 Indirect Symbols 对应的位置。
 从中我们可以获取到指定符号的偏移量，这个偏移量主要用来在 String Table 中检索出符号名称字符串。
 之后我们找到 __DATA.__la_symbol_ptr 和 __DATA.__la_symbol_ptr 这两个 Section。
 这两个表中，都是由 Indirect Pointer 构成的指针数组，但是其中的元素决定了我们调用的方法应该以哪个代码段的方法来执行。
 我们遍历这个指针数组中每一个指针，在每一层遍历中取出其符号名称，与我们的 rebindings 链表中每一个元素进行比对，当名称匹配的时候，重写其指向地址
 */

static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab) {
    // 判断是取得__DATA还是__DATA_CONST节的数据
    const bool isDataConst = strcmp(section->segname, "__DATA_CONST") == 0;
    //  Indirect Symbols 的首地址 indirect_symtab 再加上 LC_SEGMENT.__DATA 中任何一个 Section 信息的 reverved1 字段就可以获取到对应的 Indirect Address 信息
    // 间接符号表的地址 + reserved1，即得到了间接符号表中存储的所有索引。这里是一个数组，存储的是uint32_t类型元素
    // 在 Indirect Symbol 表中检索到对应位置
    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    // 获取 _DATA.__nl_symbol_ptr(或__la_symbol_ptr) Section
    // 已知其 value 是一个指针类型，整段区域用二阶指针来获取
    /// section的地址 + slide偏移量 即为la_symbol_ptr在Mach-O映射的虚拟内存中的实际地址。
    /// slide依然是该image（Mach-O文件)在虚拟内存中地址偏移量（ASLR引入）。
    /// 该指针指向另一个指针A，A指向的是所有的懒绑定符号表数组
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    vm_prot_t oldProtection = VM_PROT_READ;
    if (isDataConst) {
        oldProtection = get_protection(rebindings);
        mprotect(indirect_symbol_bindings, section->size, PROT_READ | PROT_WRITE);
    }
    // 用 size / 一阶指针来计算个数，遍历整个 Section
    /// 针对每4个或8个bytes（这跟CPU是多少位有关），进行遍历操作
    for (uint i = 0; i < section->size / sizeof(void *); i++) {
        // 通过下标来获取每一个 Indirect Address 的 Value
        // 这个 Value 也是外层寻址时需要的下标
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
            continue;
        }
         // 根据symtab_index(indirect_symbol中data的值)去访问symbol_table，获取到symbol_table中的偏移offset(即symbol_table中data的值，这个值也是字符串表中的偏移值
        // 遍历每一个 Indirect Symbols，并以索引方式获取到每一个 nlist 结构的符号，从符号中获取到符号名字符串在字符表中的偏移量，进而继续获取符号名
        // 获取符号名在字符表中的偏移地址
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        // 获取符号名
         // 访问string_table，根据strtab_offset获取symbol_name(函数名)
        char *symbol_name = strtab + strtab_offset;
        // string_table中的所有函数名都是以"_"开始的，所以一个函数一定有两个字符
        // symbol_name 长度是否大于2
        bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
        // 取出 rebindings 结构体实例数组，开始遍历链表
        struct rebindings_entry *cur = rebindings;
        while (cur) {
            // 对于链表中每一个 rebindings 数组的每一个 rebinding 实例
            // 依次在 String Table 匹配符号名
            for (uint j = 0; j < cur->rebindings_nel; j++) {
                // 符号名与方法名匹配
                if (symbol_name_longer_than_1 &&
                    strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    // 如果是第一次对跳转地址进行重写
                    if (cur->rebindings[j].replaced != NULL &&
                        indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
                        // 记录原始跳转地址
                        *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
                    }
                    // 重写跳转地址
                    indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
                    // 完成后不再对当前 Indirect Symbol 处理
                    // 继续迭代到下一个 Indirect Symbol
//                    /** 加入调试代码 **/
//                    printf("\n\nSymbol Name: %s\n", &symbol_name[1]);
//                    printf("Rebinding Name: %s\n", cur->rebindings[j].name);
//                    printf("Origin Addr: 0x%X\n", cur->rebindings[j].replaced);
//                    printf("Rebinding Addr: 0x%X\n", cur->rebindings[j].replacement);
//                    /** 调试代码 END **/
                    goto symbol_loop;
                }
            }
            // 链表遍历
            cur = cur->next;
        }
    symbol_loop:;
    }
    if (isDataConst) {
        // 如果是__DATA_CONST 节的话
        int protection = 0;
        if (oldProtection & VM_PROT_READ) {
            protection |= PROT_READ;
        }
        if (oldProtection & VM_PROT_WRITE) {
            protection |= PROT_WRITE;
        }
        if (oldProtection & VM_PROT_EXECUTE) {
            protection |= PROT_EXEC;
        }
        mprotect(indirect_symbol_bindings, section->size, protection);
    }
}
// 整个 fishhook 精华所在 - 重绑定符号过程
static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
    Dl_info info;
    if (dladdr(header, &info) == 0) {
        return;
    }
    // 声明几个查找量:
    // linkedit_segment, symtab_command, dysymtab_command
    segment_command_t *cur_seg_cmd;
    segment_command_t *linkedit_segment = NULL;
    struct symtab_command* symtab_cmd = NULL;
    struct dysymtab_command* dysymtab_cmd = NULL;
    
    // 初始化游标
    // header = 0x100000000 - 二进制文件基址默认偏移
    // sizeof(mach_header_t) = 0x20 - Mach-O Header 部分
    
    // 首先需要跳过 Mach-O Header
    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    // 遍历每一个 Load Command，游标每一次偏移每个命令的 Command Size 大小
    // header -> ncmds: Load Command 加载命令数量
    // cur_seg_cmd -> cmdsize: Load 大小
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        // 取出当前的 Load Command
        cur_seg_cmd = (segment_command_t *)cur;
        // Load Command 的类型是 LC_SEGMENT
        if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            // 比对一下 Load Command 的 name 是否为 __LINKEDIT
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                // 检索到 __LINKEDIT
                linkedit_segment = cur_seg_cmd;
            }
        }
        // 判断当前 Load Command 是否是 LC_SYMTAB 类型
        // LC_SEGMENT - 代表当前区域链接器信息
        else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            // 检索到 LC_SYMTAB
            symtab_cmd = (struct symtab_command*)cur_seg_cmd;
        }
        // 判断当前 Load Command 是否是 LC_DYSYMTAB 类型
        // LC_DYSYMTAB - 代表动态链接器信息区域
        else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            // 检索到 LC_DYSYMTAB
            dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
        }
    }
    // 容错处理
    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment ||
        !dysymtab_cmd->nindirectsyms) {
        return;
    }
    
    // Find base symbol/string table addresses
    // slide: ASLR 偏移量
    // vmaddr: SEG_LINKEDIT段的虚拟地址
    // fileoff: SEG_LINKEDIT段在Mach-O中的地址偏移
    // 式①：linkedit_base = SEG_LINKEDIT真实地址 - SEG_LINKEDIT地址偏移
    // 式②：SEG_LINKEDIT真实地址 = SEG_LINKEDIT虚拟地址 + ASLR偏移量
    // 将②代入①：linkedit_base = SEG_LINKEDIT虚拟地址 + ASLR偏移量 - SEG_LINKEDIT地址偏移
    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    /// LC_SYMTAB和LC_DYSYMTAB中所记录的Offset都是基于Mach-O在虚拟内存中的基地址的。
    /// linkedit_base + symtab_cmd->symoff 即为符号表的地址
    /// linkedit_base + symtab_cmd->stroff 即为符号表的字符串表地址
    //SymbolTable地址 通过 base + symtab 的偏移量 计算 symtab 表的首地址，并获取 nlist_t 结构体实例。
    nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
    //StringTable地址 通过 base + stroff 字符表偏移量计算字符表中的首地址，获取字符串表
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    
    // Get indirect symbol table (array of uint32_t indices into symbol table)
    //Dynamic Symbol Table地址 通过 base + indirectsymoff 偏移量来计算动态符号表的首地址
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);
    // 归零游标，复用
    cur = (uintptr_t)header + sizeof(mach_header_t);
    // 再次遍历 Load Commands
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (segment_command_t *)cur;
        // Load Command 的类型是 LC_SEGMENT
        if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            // 查询 Segment Name 过滤出 __DATA 或者 __DATA_CONST
            if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
                strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
                continue;
            }
            // 遍历 Segment 中的 Section
            for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
                // 取出 Section
                section_t *sect =
                (section_t *)(cur + sizeof(segment_command_t)) + j;
                // flags & SECTION_TYPE 通过 SECTION_TYPE 掩码获取 flags 记录类型的 8 bit
                // 如果 section 的类型为 S_LAZY_SYMBOL_POINTERS
                // 这个类型代表 lazy symbol 指针 Section
                if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
                    // 进行 rebinding 重写操作
                    perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
                }
                // 这个类型代表 non-lazy symbol 指针 Section
                if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                    perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
                }
            }
        }
    }
}
/** * _rebind_symbols_for_image 是 rebind_symbols_for_image 的一个入口方法 *
 这个入口方法存在的意义是满足 _dyld_register_func_for_add_image 传入回调方法的格式 *
 header - Mach-O 头 *
 slide - intptr_t 持有指针 */
static void _rebind_symbols_for_image(const struct mach_header *header,
                                      intptr_t slide) {
    // 外层是一个入口函数，意在调用有效的方法 rebind_symbols_for_image
    rebind_symbols_for_image(_rebindings_head, header, slide);
}

int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct rebinding rebindings[],
                         size_t rebindings_nel) {
    struct rebindings_entry *rebindings_head = NULL;
    int retval = prepend_rebindings(&rebindings_head, rebindings, rebindings_nel);
    rebind_symbols_for_image(rebindings_head, (const struct mach_header *) header, slide);
    if (rebindings_head) {
        free(rebindings_head->rebindings);
    }
    free(rebindings_head);
    return retval;
}

/** * rebind_symbols * struct rebinding rebindings[] - rebinding 结构体数组 * size_t rebindings_nel - 数组长度 */
int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
    // 维护一个 rebindings_entry 的结构
    // 将 rebinding 的多个实例组织成一个链表，内部算法为头插法
    int retval = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
    // 判断是否 malloc 失败，失败会返回 -1
    if (retval < 0) {
        return retval;
    }
    // 在执行完链表的初始化及结构维护的 prepend_rebindings 方法，继续执行
    // 由于我们的 strlen 是 dyld 加载的系统库方法，所以 _rebindings_head -> next 在第一次调用的时候为空
    // 因为没有做过替换符号，所以会调用 _dyld_register_func_for_add_image 来注册 _rebind_symbols_for_image 方法，
    // 之后程序每次加载动态库的时候，都会去调用该方法。如果不是第一次替换符号，则遍历已经加载的动态库
    
    // If this was the first call, register callback for image additions (which is also invoked for
    // existing images, otherwise, just run on existing images
    // _rebindings_head -> next 是第一次调用的标志符，NULL 则代表第一次调用
    if (!_rebindings_head->next) {
        // 第一次调用，将 _rebind_symbols_for_image 注册为回调
        // _dyld_register_func_for_add_image 这个方法当镜像 Image 被 load 或是 unload 的时候都会由 dyld 主动调用
        // 当该方法被触发时，会为每个镜像触发其回调方法。之后则将其镜像与其回屌函数进行绑定（但是未进行初始化）
        // 使用 _dyld_register_func_for_add_image 注册的回调将在镜像中的 terminators 启动后被调用
        _dyld_register_func_for_add_image(_rebind_symbols_for_image);
    } else {
        // 先获取 dyld 镜像数量
        uint32_t c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++) {
            // 根据下标依次进行重绑定过程
            _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
    }
    // 返回状态值
    return retval;
}
