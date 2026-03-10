<script>
  let { size = 24 } = $props()
</script>

<span class="spinner" style="width:{size}px;height:{size}px"></span>

<style>
  .spinner {
    display: inline-block;
    border: 1px solid var(--color-text-muted);
    border-right-color: transparent;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>
