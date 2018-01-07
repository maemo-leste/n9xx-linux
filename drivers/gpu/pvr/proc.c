/**********************************************************************
 *
 * Copyright(c) 2008 Imagination Technologies Ltd. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful but, except
 * as otherwise stated in writing, without any warranty; without even the
 * implied warranty of merchantability or fitness for a particular purpose.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * Imagination Technologies Ltd. <gpl-support@imgtec.com>
 * Home Park Estate, Kings Langley, Herts, WD4 8LZ, UK
 *
 ******************************************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>

#include "services_headers.h"

#include "queue.h"
#include "resman.h"
#include "pvrmmap.h"
#include "pvr_debug.h"
#include "pvrversion.h"
#include "proc.h"
#include "perproc.h"
#include "env_perproc.h"

/* The proc entry for our /proc/pvr directory */

static struct proc_dir_entry *dir;

static void procDumpSysNodes(struct seq_file *sfile, void* el);
static void procDumpVersion(struct seq_file *sfile, void* el);

static const char PVRProcDirRoot[] = "pvr";

static void *pvr_proc_seq_start (struct seq_file *m, loff_t *pos);
static void pvr_proc_seq_stop (struct seq_file *m, void *v);
static void *pvr_proc_seq_next (struct seq_file *m, void *v, loff_t *pos);
static int pvr_proc_seq_show (struct seq_file *m, void *v);

static int pvr_proc_open(struct inode *inode,struct file *file);
static ssize_t pvr_proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos);

static void* ProcSeqOff2ElementSysNodes(struct seq_file * sfile, loff_t off);

static struct file_operations pvr_proc_operations =
{
	.open		= pvr_proc_open,
	.read		= seq_read,
	.write		= pvr_proc_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static struct seq_operations pvr_proc_seq_operations =
{
	.start =	pvr_proc_seq_start,
	.next =		pvr_proc_seq_next,
	.stop =		pvr_proc_seq_stop,
	.show =		pvr_proc_seq_show,
};

/*!
******************************************************************************

 @Function : pvr_proc_open

 @Description
 File opening function passed to proc_dir_entry->proc_fops for /proc entries
 created by CreateProcReadEntrySeq.

 @Input  inode : inode entry of opened /proc file

 @Input  file : file entry of opened /proc file

 @Return      : 0 if no errors

*****************************************************************************/
static int pvr_proc_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &pvr_proc_seq_operations);
	struct seq_file *seq = (struct seq_file *)file->private_data;

	PVR_PROC_SEQ_HANDLERS *data = (PVR_PROC_SEQ_HANDLERS *)PDE_DATA(inode);
	seq->private = data;

	return ret;
}

/*!
******************************************************************************

 @Function : pvr_proc_write

 @Description
 File writing function passed to proc_dir_entry->proc_fops for /proc files.
 It's exacly the same function that is used as default one (->fs/proc/generic.c),
 it calls proc_dir_entry->write_proc for writing procedure.

*****************************************************************************/
static ssize_t pvr_proc_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_path.dentry->d_inode;

	PVR_PROC_SEQ_HANDLERS *data = (PVR_PROC_SEQ_HANDLERS *)PDE_DATA(inode);
	PVR_UNREFERENCED_PARAMETER(ppos);

	if (!data->write_proc)
		return -EIO;

	return data->write_proc(file, buffer, count, data);
}


/*!
******************************************************************************

 @Function : pvr_proc_seq_start

 @Description
 Seq_file start function. Detailed description of seq_file workflow can
 be found here: http://tldp.org/LDP/lkmpg/2.6/html/x861.html.
 This function ises off2element handler.

 @Input  proc_seq_file : sequence file entry

 @Input  pos : offset within file (id of entry)

 @Return      : Pointer to element from we start enumeration (0 ends it)

*****************************************************************************/
static void *pvr_proc_seq_start (struct seq_file *proc_seq_file, loff_t *pos)
{
	PVR_PROC_SEQ_HANDLERS *handlers =
			(PVR_PROC_SEQ_HANDLERS *)proc_seq_file->private;

	if(handlers->startstop != NULL)
		handlers->startstop(proc_seq_file, IMG_TRUE);

	return handlers->off2element(proc_seq_file, *pos);
}

/*!
******************************************************************************

 @Function : pvr_proc_seq_stop

 @Description
 Seq_file stop function. Detailed description of seq_file workflow can
 be found here: http://tldp.org/LDP/lkmpg/2.6/html/x861.html.

 @Input  proc_seq_file : sequence file entry

 @Input  v : current element pointer

*****************************************************************************/
static void pvr_proc_seq_stop (struct seq_file *proc_seq_file, void *v)
{
	PVR_PROC_SEQ_HANDLERS *handlers =
			(PVR_PROC_SEQ_HANDLERS *)proc_seq_file->private;
	PVR_UNREFERENCED_PARAMETER(v);

	if (handlers->startstop != NULL)
		handlers->startstop(proc_seq_file, IMG_FALSE);
}

/*!
******************************************************************************

 @Function : pvr_proc_seq_next

 @Description
 Seq_file next element function. Detailed description of seq_file workflow can
 be found here: http://tldp.org/LDP/lkmpg/2.6/html/x861.html.
 It uses supplied 'next' handler for fetching next element (or 0 if there is no one)

 @Input  proc_seq_file : sequence file entry

 @Input  pos : offset within file (id of entry)

 @Input  v : current element pointer

 @Return   : next element pointer (or 0 if end)

*****************************************************************************/
static void *pvr_proc_seq_next (struct seq_file *proc_seq_file, void *v, loff_t *pos)
{
	PVR_PROC_SEQ_HANDLERS *handlers =
			(PVR_PROC_SEQ_HANDLERS *)proc_seq_file->private;

	(*pos)++;

	if (handlers->next != NULL)
		return handlers->next(proc_seq_file, v, *pos);

	return handlers->off2element(proc_seq_file, *pos);
}

/*!
******************************************************************************

 @Function : pvr_proc_seq_show

 @Description
 Seq_file show element function. Detailed description of seq_file workflow can
 be found here: http://tldp.org/LDP/lkmpg/2.6/html/x861.html.
 It call proper 'show' handler to show (dump) current element using seq_* functions

 @Input  proc_seq_file : sequence file entry

 @Input  v : current element pointer

 @Return   : 0 if everything is OK

*****************************************************************************/
static int pvr_proc_seq_show (struct seq_file *proc_seq_file, void *v)
{
	PVR_PROC_SEQ_HANDLERS *handlers =
			(PVR_PROC_SEQ_HANDLERS *)proc_seq_file->private;

	handlers->show( proc_seq_file,v );

    return 0;
}

off_t printAppend(char *buffer, size_t size, off_t off, const char *format, ...)
{
	int n;
	int space = size - off;
	va_list ap;

	PVR_ASSERT(space >= 0);

	va_start(ap, format);
	n = vsnprintf(buffer + off, space, format, ap);
	va_end(ap);

	if (n >= space || n < 0) {

		buffer[size - 1] = 0;
		return size - 1;
	} else {
		return off + n;
	}
}

static struct proc_dir_entry *CreateProcEntryInDir(
		struct proc_dir_entry *pdir, const char *name, void* data,
		pvr_next_proc_seq_t next_handler,
		pvr_show_proc_seq_t show_handler,
		pvr_off2element_proc_seq_t off2element_handler,
		pvr_startstop_proc_seq_t startstop_handler,
		write_proc_t whandler)
{

    struct proc_dir_entry * file;
	mode_t mode;
	PVR_PROC_SEQ_HANDLERS *seq_handlers;

    if (!dir)
    {
	PVR_DPF(PVR_DBG_ERROR,
		"CreateProcEntryInDir: cannot make proc entry /proc/%s/%s: no parent",
		PVRProcDirRoot, name);
	return NULL;
    }

	mode = S_IFREG;

    if (show_handler)
    {
		mode |= S_IRUGO;
    }

    if (whandler)
    {
		mode |= S_IWUSR;
    }

	seq_handlers = (PVR_PROC_SEQ_HANDLERS*)
		       kmalloc(sizeof(PVR_PROC_SEQ_HANDLERS), GFP_KERNEL);

	if (seq_handlers)
	{
		seq_handlers->next = next_handler;
		seq_handlers->show = show_handler;
		seq_handlers->off2element = off2element_handler;
		seq_handlers->startstop = startstop_handler;
		seq_handlers->data = data;
		seq_handlers->write_proc = whandler;
		file = proc_create_data(name, mode, pdir, &pvr_proc_operations,
					seq_handlers);
		if (file)
			return file;

		kfree(seq_handlers);
	}

    PVR_DPF(PVR_DBG_ERROR,
	    "CreateProcEntryInDir: cannot make proc entry /proc/%s/%s: no memory",
	    PVRProcDirRoot, name);

    return NULL;
}

struct proc_dir_entry *CreateProcEntry(
		const char *name, void* data, pvr_next_proc_seq_t next_handler,
		pvr_show_proc_seq_t show_handler,
		pvr_off2element_proc_seq_t off2element_handler,
		pvr_startstop_proc_seq_t startstop_handler,
		write_proc_t whandler)
{
	return CreateProcEntryInDir(dir, name, data, next_handler, show_handler,
				    off2element_handler, startstop_handler,
				    whandler);
}

static struct proc_dir_entry *
ProcessProcDirCreate(u32 pid)
{
	struct PVRSRV_ENV_PER_PROCESS_DATA *psPerProc;
	char dirname[16];
	int ret;

	psPerProc = PVRSRVPerProcessPrivateData(pid);
	if (!psPerProc) {
		pr_err("%s: no per process data for %d\n", __func__, pid);
		return NULL;
	}

	if (psPerProc->psProcDir)
		return psPerProc->psProcDir;

	ret = snprintf(dirname, sizeof(dirname), "%u", pid);
	if (ret <= 0 || ret >= sizeof(dirname)) {
		pr_err("%s: couldn't generate per process proc dir for %d\n",
		       __func__, pid);
		return NULL;
	}

	psPerProc->psProcDir = proc_mkdir(dirname, dir);
	if (!psPerProc->psProcDir)
		pr_err("%s: couldn't create /proc/%s/%u\n",
		       __func__, PVRProcDirRoot, pid);

	return psPerProc->psProcDir;
}

static struct proc_dir_entry *
ProcessProcDirGet(u32 pid)
{
	struct PVRSRV_ENV_PER_PROCESS_DATA *psPerProc;

	psPerProc = PVRSRVPerProcessPrivateData(pid);
	if (!psPerProc) {
		pr_err("%s: no per process data for %d\n", __func__, pid);
		return NULL;
	}

	if (!psPerProc->psProcDir) {
		pr_err("%s: couldn't retrieve /proc/%s/%u\n", __func__,
		       PVRProcDirRoot, pid);
		return NULL;
	}

	return psPerProc->psProcDir;
}

struct proc_dir_entry *CreatePerProcessProcEntry(
		u32 pid, const char *name, void* data,
		pvr_next_proc_seq_t next_handler,
		pvr_show_proc_seq_t show_handler,
		pvr_off2element_proc_seq_t off2element_handler,
		pvr_startstop_proc_seq_t startstop_handler,
		write_proc_t whandler)
{
	struct proc_dir_entry *pid_dir = dir;

	if (!dir) {
		PVR_DPF(PVR_DBG_ERROR,
			 "CreatePerProcessProcEntries: /proc/%s doesn't exist",
			 PVRProcDirRoot);

		return NULL;
	}

	if (pid) {
		pid_dir = ProcessProcDirCreate(pid);

		if (!pid_dir)
			return NULL;
	}

	return CreateProcEntryInDir(pid_dir, name, data, next_handler,
				    show_handler, off2element_handler,
				    startstop_handler, whandler);
}

struct proc_dir_entry *CreateProcReadEntry(
		const char* name, void* data, pvr_next_proc_seq_t next_handler,
		pvr_show_proc_seq_t show_handler,
		pvr_off2element_proc_seq_t off2element_handler,
		pvr_startstop_proc_seq_t startstop_handler)
{
	return CreateProcEntry(name, data, next_handler, show_handler,
			       off2element_handler,startstop_handler, NULL);
}

int CreateProcEntries(void)
{
	dir = proc_mkdir(PVRProcDirRoot, NULL);

	if (!dir) {
		PVR_DPF(PVR_DBG_ERROR,
			 "CreateProcEntries: cannot make /proc/%s directory",
			 PVRProcDirRoot);

		return -ENOMEM;
	}

	if (!CreateProcReadEntry("queue", NULL, NULL, QueuePrintQueues,
				 ProcSeqOff2ElementQueue, NULL) ||
	    !CreateProcReadEntry("version", NULL, NULL, procDumpVersion,
				 ProcSeq1ElementHeaderOff2Element, NULL) ||
	    !CreateProcReadEntry("nodes", NULL, NULL, procDumpSysNodes,
				 ProcSeqOff2ElementSysNodes, NULL)) {
		PVR_DPF(PVR_DBG_ERROR,
			 "CreateProcEntries: couldn't make /proc/%s files",
			 PVRProcDirRoot);

		return -ENOMEM;
	}
#ifdef CONFIG_PVR_DEBUG_EXTRA
	if (CreateProcEntry
	    ("debug_level", PVRDebugProcGetLevel, PVRDebugProcSetLevel, NULL)) {
		PVR_DPF(PVR_DBG_ERROR,
			"CreateProcEntries: couldn't make /proc/%s/debug_level",
			 PVRProcDirRoot);

		return -ENOMEM;
	}
#endif

	return 0;
}

void RemoveProcEntry(const char *name)
{
	if (dir) {
		remove_proc_entry(name, dir);
		PVR_DPF(PVR_DBG_MESSAGE, "Removing /proc/%s/%s",
			 PVRProcDirRoot, name);
	}
}

void RemovePerProcessProcEntry(u32 pid, const char *name)
{
	if (pid) {
		struct proc_dir_entry *pid_dir = ProcessProcDirGet(pid);

		if (!pid_dir)
			return;

		remove_proc_entry(name, pid_dir);

		PVR_DPF(PVR_DBG_MESSAGE, "Removing proc entry %s", name);
	} else
		RemoveProcEntry(name);
}

void RemovePerProcessProcDir(struct PVRSRV_ENV_PER_PROCESS_DATA *psPerProc)
{
	if (psPerProc->psProcDir)
		proc_remove(psPerProc->psProcDir);
}

void RemoveProcEntries(void)
{
	remove_proc_subtree(PVRProcDirRoot, NULL);
}

static void procDumpVersion(struct seq_file *sfile, void* el)
{
	struct SYS_DATA *psSysData;

	if (el == PVR_PROC_SEQ_START_TOKEN) {
		seq_printf(sfile, "Version %s (%s) %s\n", PVRVERSION_STRING,
			   PVR_BUILD_TYPE, PVR_BUILD_DIR);
		return;
	} else {
		char *pszSystemVersionString = "None";

		if (SysAcquireData(&psSysData) != PVRSRV_OK)
			return;

		if (psSysData->pszVersionString)
			pszSystemVersionString = psSysData->pszVersionString;

		seq_printf(sfile, "System Version String: %s\n",
			   pszSystemVersionString);
	}
}

static const char *deviceTypeToString(enum PVRSRV_DEVICE_TYPE deviceType)
{
	switch (deviceType) {
	default:
		{
			static char text[10];
			sprintf(text, "?%x", deviceType);
			return text;
		}
	}
}

static const char *deviceClassToString(enum PVRSRV_DEVICE_CLASS deviceClass)
{
	switch (deviceClass) {
	case PVRSRV_DEVICE_CLASS_3D:
		{
			return "3D";
		}
	case PVRSRV_DEVICE_CLASS_DISPLAY:
		{
			return "display";
		}
	case PVRSRV_DEVICE_CLASS_BUFFER:
		{
			return "buffer";
		}
	default:
		{
			static char text[10];

			sprintf(text, "?%x", deviceClass);
			return text;
		}
	}
}

static void procDumpSysNodes(struct seq_file *sfile, void* el)
{
	struct SYS_DATA *psSysData;
	struct PVRSRV_DEVICE_NODE *psDevNode;

	if (el == PVR_PROC_SEQ_START_TOKEN) {
		seq_printf(sfile, "Registered nodes\n"
		"Addr     Type     Class    Index Ref pvDev     Size Res\n");
		return;
	}

	if (SysAcquireData(&psSysData) != PVRSRV_OK)
		return;

	psDevNode = (struct PVRSRV_DEVICE_NODE*)el;

	seq_printf(sfile, "%p %-8s %-8s %4d  %2u  %p  %3u  %p\n", psDevNode,
		  deviceTypeToString(psDevNode->sDevId.eDeviceType),
		  deviceClassToString(psDevNode->sDevId.eDeviceClass),
		  psDevNode->sDevId.eDeviceClass,
		  psDevNode->ui32RefCount,
		  psDevNode->pvDevice,
		  psDevNode->ui32pvDeviceSize,
		  psDevNode->hResManContext);
}

void* ProcSeq1ElementHeaderOff2Element(struct seq_file *sfile, loff_t off)
{
	PVR_UNREFERENCED_PARAMETER(sfile);

	if(!off)
	{
		return PVR_PROC_SEQ_START_TOKEN;
	}

	// Return anything that is not PVR_RPOC_SEQ_START_TOKEN and NULL
	if(off == 1)
		return (void*)2;

	return NULL;
}

static void* ProcSeqOff2ElementSysNodes(struct seq_file * sfile, loff_t off)
{
    struct SYS_DATA *psSysData;
    struct PVRSRV_DEVICE_NODE*psDevNode = NULL;

    PVR_UNREFERENCED_PARAMETER(sfile);

    if (!off)
	return PVR_PROC_SEQ_START_TOKEN;

    SysAcquireData(&psSysData);

    if (psSysData)
    {
	    for (psDevNode = psSysData->psDeviceNodeList;
		 --off && psDevNode; psDevNode = psDevNode->psNext);
    }

    /* Return anything that is not PVR_RPOC_SEQ_START_TOKEN and NULL */
    return (void*)psDevNode;
}
