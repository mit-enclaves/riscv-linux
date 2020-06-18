#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/fs.h>
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/err.h>

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/cma.h>
#include <linux/spinlock.h>
#include <linux/irqflags.h>

#include "api/api_untrusted.h"

#include "platform/parameters.h"

//#define PAGE_SIZE (1<<PAGE_SHIFT)
#define REGION_SIZE (1<<REGION_SHIFT)
#define REGION_MASK (~(REGION_SIZE-1))

static inline uint64_t addr_to_region_id (uintptr_t addr) {
  return ((addr-RAM_BASE) & REGION_MASK) >> REGION_SHIFT; // will return an illegally large number in case of an address outside RAM. CAUTION!
}

static inline void * region_id_to_addr (uint64_t region_id) {
  return (void *)(RAM_BASE + (region_id << REGION_SHIFT));
}


struct arg_start_enclave { api_result_t result; uintptr_t enclave_start; uintptr_t enclave_end; };
#define MAJOR_NUM 's'
#define IOCTL_START_ENCLAVE _IOR(MAJOR_NUM, 0x1, struct arg_stat_enclave*)

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Computer Structure Group CSAIL");
MODULE_DESCRIPTION("Security Monitor");


static struct device *security_monitor_dev;

static uintptr_t region1 = 0;
static uintptr_t region2 = 0;
static api_result_t start_enclave(uintptr_t enclave_start, uintptr_t enclave_end, uintptr_t enclave_hash)
{

  uint64_t region1_id;
  uint64_t region_metadata_start;
  enclave_id_t enclave_id;
  uint64_t num_mailboxes = 1;
  uint64_t timer_limit = 10000000;
  uint64_t region2_id;
  uintptr_t enclave_handler_address;
  uintptr_t enclave_handler_stack_pointer;
  uintptr_t page_table_address;
  uintptr_t phys_addr;
  uintptr_t os_addr;
  uintptr_t virtual_addr = 0;
  int num_pages_enclave;
  uintptr_t entry_stack; 
  uintptr_t stack_phys_addr;
  uintptr_t enclave_stack;
  uintptr_t entry_pc;
  int page_count;
  uint64_t size_enclave_metadata;
  thread_id_t thread_id;
  api_result_t result = 0;

  printk(KERN_INFO "Start routine start_enclave");
  if(region1 ==0 && region2 == 0) {
  dma_addr_t dma_addr = 0;
  void* addr = dma_alloc_coherent(security_monitor_dev, 0x5000000, &dma_addr, GFP_KERNEL);

  if (dma_addr == 0) {
    printk(KERN_ALERT "Error allocation");
    return result;
  }
  printk(KERN_INFO "dma addr is %lx",(long)dma_addr);
  if ( (unsigned long long) addr % 0x2000000 == 0) {
    region1 = (uintptr_t) dma_addr;
    region2 = (uintptr_t) dma_addr+0x2000000;
  } else {
    unsigned long long aligned_dma_addr = ((((unsigned long long) dma_addr)/0x2000000)+1)*0x2000000; 
    region1 = (uintptr_t) aligned_dma_addr;
    region2 = (uintptr_t) aligned_dma_addr+0x2000000;
  }
  printk(KERN_INFO "Address region1 is %lx",region1);
  printk(KERN_INFO "Address region2 is %lx",region2);
  region2_id = addr_to_region_id((uintptr_t) region2);
  result = sm_region_block(region2_id);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_block FAILED with error code %d\n", result);
    return result; 
  }

  result = sm_region_free(region2_id);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_free FAILED with error code %d\n ", result);
    return result;
  }

  result = sm_region_metadata_create(region2_id);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_metadata_create FAILED with error code %d\n",result);
    return result; 
  }
  }
  region1_id = addr_to_region_id((uintptr_t) region1);
  region_metadata_start = sm_region_metadata_start();
  printk(KERN_INFO "Address metadata is %lx", (long)region_metadata_start);
  enclave_id = ((uintptr_t) region2) + (PAGE_SIZE * region_metadata_start);

  result = sm_enclave_create(enclave_id, 0x0, ~0xFFFFFF/*REGION_MASK*/, num_mailboxes, timer_limit, true);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_create FAILED with error code %d\n", result);
    return result;
  }

  result = sm_region_block(region1_id);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_block FAILED with error code %d\n", result);
    return result;
  }

  result = sm_region_free(region1_id);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_free FAILED with error code %d\n", result);
    return result; 
  }

  result = sm_region_assign(region1_id, enclave_id);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_assign FAILED with error code %d\n", result);
    return result; 
  }

  enclave_handler_address = (uintptr_t) region1;
  page_table_address = enclave_handler_address + HANDLER_LEN + STACK_SIZE;
  enclave_handler_stack_pointer = page_table_address - INTEGER_CONTEXT_SIZE;

  result = sm_enclave_load_handler(enclave_id, enclave_handler_address);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_load_handler FAILED with error code %d\n", result);
    return result; 
  }

  printk(KERN_INFO "Enclave Page Table Root is %lx",(long)page_table_address);

  result = sm_enclave_load_page_table(enclave_id, page_table_address, 0, 3, NODE_ACL);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_load_page_table FAILED with error code %d\n", result);
    return result; 
  }

  page_table_address += PAGE_SIZE;

  result = sm_enclave_load_page_table(enclave_id, page_table_address, 0, 2, NODE_ACL);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_load_page_table FAILED with error code %d\n", result);
    return result; 
  }

  page_table_address += PAGE_SIZE;

  result = sm_enclave_load_page_table(enclave_id, page_table_address, 0, 1, NODE_ACL);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_load_page_table FAILED with error code %d\n", result);
    return result; 
  }

  phys_addr = page_table_address + PAGE_SIZE;
  os_addr = enclave_start;
  virtual_addr = 0;

  printk(KERN_INFO "Start loading program\n");

  
  num_pages_enclave = ((((uint64_t) enclave_end) - ((uint64_t) enclave_start)) / PAGE_SIZE);
  
  if(((((uint64_t) enclave_end) - ((uint64_t) enclave_start)) % PAGE_SIZE) != 0) {
    printk(KERN_ALERT "Enclave binary is not page aligned");
    return result;
  }
  
  // Load page table entry for stack
  entry_stack = 0x200000; 
  stack_phys_addr = phys_addr;
  result = sm_enclave_load_page_table(enclave_id, stack_phys_addr, entry_stack - PAGE_SIZE, 0, LEAF_ACL);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_load_page_table FAILED with error code %d\n", result);
    return result; 
  }

  phys_addr += PAGE_SIZE;
  enclave_stack = virtual_addr;
  printk(KERN_INFO "Enclave Stack Pointer %lx\n", enclave_stack);
  
  

  entry_pc = virtual_addr;
  
  uint64_t nonce_addr = enclave_end;
  for(page_count = 0; page_count < num_pages_enclave; page_count++) {

    result = sm_enclave_load_page(enclave_id, phys_addr, virtual_addr, os_addr, LEAF_ACL, nonce_addr);
    if(result != MONITOR_OK) {
      printk(KERN_ALERT "sm_enclave_load_page FAILED with error code %d\n", result);
      return result; 
    }

    printk(KERN_INFO "Just loaded page %x at address %x\n", page_count, phys_addr);
    phys_addr    += PAGE_SIZE;
    os_addr      += PAGE_SIZE;
    virtual_addr += PAGE_SIZE;
    nonce_addr += 16;
  }

  size_enclave_metadata = sm_enclave_metadata_pages(num_mailboxes);

  thread_id = enclave_id + (size_enclave_metadata * PAGE_SIZE);
  
  result = sm_thread_load(enclave_id, thread_id, entry_pc, entry_stack, enclave_handler_address, enclave_handler_stack_pointer);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_thread_load FAILED with error code %d\n", result);
    return result; 
  }

  printk(KERN_INFO "Enclave init\n");
  result = sm_enclave_init(enclave_id);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_init FAILED with error code %d\n", result);
    return result; 
  }
  printk(KERN_INFO "Enclave enter\n");
  // the hash is after the nonces
  enclave_hash = enclave_end + num_pages_enclave * 16;
  result = sm_enclave_enter(enclave_id, thread_id, enclave_hash);
  printk(KERN_INFO "Enclaved finished executing with : %d\n", result); 

  result = sm_thread_delete(thread_id);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_thread_delete FAILED with error code %d\n", result);
    return result;
  }

  printk(KERN_INFO "delete thread\n");
  result = sm_enclave_delete(enclave_id);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_enclave_delete FAILED with error code %d\n", result);
    return result; 
  }

  printk(KERN_INFO "delete enclave\n");

  result = sm_region_assign(region1_id, OWNER_UNTRUSTED);
  if(result != MONITOR_OK) {
    printk(KERN_ALERT "sm_region_assign FAILED with error code %d\n", result);
    return result; 
  }
  printk(KERN_INFO "reassign region to untrusted \n");

  //dma_free_coherent(security_monitor_dev, 0x5000000,  addr, dma_addr);
  return result;
}

static long sm_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static ssize_t sm_read(struct file * file, char * buf, size_t count, loff_t *ppos){
    printk(KERN_INFO "read dummy sm");
    return 0;
}
static struct file_operations fops =
  {
   .owner          = THIS_MODULE,
   .read           = sm_read,
   .write          = NULL,
   .open           = NULL,
   .unlocked_ioctl = sm_ioctl,
   .release        = NULL,
  };


static struct miscdevice security_monitor_misc = {
        .name = "security_monitor",
        .fops = &fops,
    .minor =  MISC_DYNAMIC_MINOR,
};

static long sm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
        //local_irq_disable();

        unsigned long bytes_from_user;
        unsigned long bytes_to_user;

        struct arg_start_enclave arg_struct;
         switch(cmd) {
         case IOCTL_START_ENCLAVE: {
                        dma_addr_t dma_addr;
                        size_t size_enclave;
                        void* addr;
                        int iterateword;
                        uint8_t measurement[] = {
                          0x51, 0xce, 0x5e, 0x9a, 0x4c, 0xf5, 0x5f, 0x81, 0x70, 0x2d, 0x0d, 0xd6, 0x2a, 0x77, 0x7a, 0x68,
                          0x4a, 0xf3, 0x6a, 0x3b, 0xc9, 0xef, 0x51, 0x48, 0x44, 0x21, 0xa5, 0xca, 0xdc, 0xcb, 0x67, 0xc0,
                          0xeb, 0x9c, 0x7b, 0x8c, 0xd2, 0x7a, 0xc5, 0xad, 0x0f, 0x81, 0xbc, 0x5e, 0x2f, 0xf9, 0x2f, 0xf3,
                          0x38, 0xdc, 0x7f, 0x95, 0x06, 0x95, 0xa7, 0x99, 0x9c, 0x7a, 0x10, 0x85, 0x64, 0x74, 0x06, 0xe8
                        };
                        bytes_from_user = copy_from_user(&arg_struct ,(int32_t*) arg, sizeof(arg_struct));
                        if (bytes_from_user != 0) {
                                printk(KERN_ALERT "Error while trying to copy argument from user space to kernel space\n" );
                        }

                        size_enclave =  arg_struct.enclave_end - arg_struct.enclave_start;

                        printk(KERN_INFO "Allocate physical memory for binary image (%ld bytes + 4096)\n", size_enclave);
                        addr = dma_alloc_coherent(security_monitor_dev, size_enclave + PAGE_SIZE, &dma_addr, GFP_KERNEL);
                        if (addr == 0) {
                          printk(KERN_ALERT "Error dma allocation");
                          return -ENOMEM;
                        }
                        printk(KERN_INFO "Copy image from user\n");
                        bytes_from_user = copy_from_user(addr, (char*) arg_struct.enclave_start, size_enclave + 4096);
                        
                        if (0) {
                                printk(KERN_INFO "Copy measurement from user\n");
                                memcpy(addr + size_enclave, measurement, sizeof(measurement));
                        }

                        if (bytes_from_user != 0) {
                                printk(KERN_ALERT "Error while trying to copy argument from user space to kernel space\n" );
                        }
                        for (iterateword = 0; iterateword < 20; iterateword++) {
                            printk(KERN_INFO "In kernel space: %x", *(((unsigned int*) addr)+ iterateword));
                        }
                        arg_struct.enclave_start = dma_addr;
                        arg_struct.enclave_end = dma_addr + size_enclave;
                        printk(KERN_INFO "Start enclave\n");
                        start_enclave(dma_addr, dma_addr + size_enclave, dma_addr + size_enclave);
                        printk(KERN_INFO "Free physical memory for binary image\n");
                        dma_free_coherent(security_monitor_dev, size_enclave, addr, dma_addr);
                        bytes_to_user = copy_to_user((void*) arg, &arg_struct, sizeof(arg_struct));
                        if (bytes_to_user != 0) {
                                printk(KERN_ALERT "Error while trying to copy argument from user space to kernel space\n" );
                        }
         }
           break;
        }
        //local_irq_enable();
        printk(KERN_INFO "reenable timer interrupts\n");
        return 0;
}


static int __init sm_mod_init(void)
{
  int ret_val;

#ifdef LKM_SM_DEBUG
  int region;
  printk(KERN_INFO "Kernel module try to do some enclave stuff!\n");
  for(region = 0; region < 64; region++) {
    int result = sm_region_owner(region);
    printk(KERN_INFO "Owner of region %d is %d\n", region, result);
  }
#endif

  ret_val = misc_register(&security_monitor_misc);
  if (unlikely(ret_val)) {
        pr_err("failed to register security monitor misc device!\n");
        return ret_val;
  }
  security_monitor_dev = security_monitor_misc.this_device;
  security_monitor_dev->coherent_dma_mask = ~0;
  _dev_info(security_monitor_dev, "registered.\n");

  return 0;
}

static void __exit sm_mod_cleanup(void)
{
  _dev_info(security_monitor_dev, "Cleaning up module.\n");

  misc_deregister(&security_monitor_misc);}

module_init(sm_mod_init);
module_exit(sm_mod_cleanup);
