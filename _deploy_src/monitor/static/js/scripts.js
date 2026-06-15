function copyShareLink(token) {
  navigator.clipboard.writeText(location.origin + '/tools/share/' + token).then(function() {
    var btn = event.currentTarget;
    var orig = btn.innerHTML;
    btn.innerHTML = '<i class="bi bi-check me-1"></i>복사됨';
    setTimeout(function() { btn.innerHTML = orig; }, 2000);
  });
}
