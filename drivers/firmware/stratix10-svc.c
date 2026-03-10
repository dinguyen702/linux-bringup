#include <linux/wait.h>

struct stratix10_svc_chan {
    wait_queue_head_t svc_wq;
    // other existing members...
};

void probe(struct stratix10_svc_chan *chans, int i) {
    init_waitqueue_head(&chans[i].svc_wq);
    // existing probe code...
}

void svc_normal_to_secure_thread(struct stratix10_svc_chan *chan) {
    while (true) {
        wait_event_interruptible(chan->svc_wq, kthread_should_stop() || !kfifo_is_empty(&chan->svc_fifo));
        if (kthread_should_stop()) break;
        // existing busy polling loop logic...
    }
}

void stratix10_svc_send(struct stratix10_svc_chan *chan) {
    // existing logic...
    kfifo_in_spinlocked(&chan->svc_fifo, data, size);
    wake_up_interruptible(&chan->svc_wq);
}

void stratix10_svc_done(struct stratix10_svc_chan *chan) {
    // leave as no-op with a comment explaining this...
}

void stratix10_svc_drv_remove(struct stratix10_svc_chan *ctrl) {
    for (int i = 0; i < ctrl->num_chans; i++) {
        wake_up_interruptible(&ctrl->chans[i].svc_wq);
    }
    kthread_stop(ctrl->task);
}

void stratix10_svc_free_memory(struct stratix10_svc_chan *svc_data_mem) {
    // instead just return if not found...
    if (!kaddr) {
        dev_warn(ctrl->dev, "Memory not found");
        return;
    }
    list_del(&svc_data_mem);
}