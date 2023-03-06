<script lang="ts">
    export let text: string
</script>

<div class="level">
    <div class="level-left">
        <div class="level-item">
            <h1 class="title">{text}</h1>
        </div>
        <div class="level-item">
            <slot name="left"/>
        </div>
    </div>
    <div class="level-right">
        <div class="level-item">
            <slot name="right"/>
        </div>
    </div>
</div>

<style>
    .level {
        min-height: 2.5em;
    }
</style>