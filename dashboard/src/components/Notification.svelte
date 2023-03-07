<script lang="ts">
    interface Notification {
        text: string,
        timer: number,
    }

    let errorNotification: Notification, 
        messageNotification: Notification

    const NOTIFICATION_TIMEOUT = 5000

    export function showError(error: string, timeout: number = NOTIFICATION_TIMEOUT) {
        if (errorNotification) {
            clearTimeout(errorNotification.timer)
        }
        errorNotification = {
            text: error,
            timer: setTimeout(() => {
                hideError()
            }, timeout)
        }        
    }

    export function hideError() {
        errorNotification = null
    }

    export function showMessage(message: string, timeout: number = NOTIFICATION_TIMEOUT) {
        if (messageNotification) {
            clearTimeout(messageNotification.timer)
        }
        messageNotification = {
            text: message,
            timer: setTimeout(() => {
                hideMessage()
            }, timeout)
        } 
    }

    export function hideMessage() {
        messageNotification = null
    }
</script>

{#if messageNotification}
<div class="notification is-success">
    <button class="delete" on:click={() => hideMessage()}></button>
    {messageNotification.text}
</div>
{/if}

{#if errorNotification}
<div class="notification is-warning">
    <button class="delete" on:click={() => hideError()}></button>
    {errorNotification.text}
</div>
{/if}

<style>
    .notification {
        position: fixed;
        left: 0;
        top: 0;
        right: 0;
        margin: auto;
        z-index: 100;
        width: fit-content;
    }
</style>