document.addEventListener("DOMContentLoaded", function () {
  const notificationIcon = document.getElementById("notification-icon");
  const notificationDropdown = document.getElementById("notification-dropdown");

  notificationIcon.addEventListener("click", function (event) {
    event.stopPropagation();
    notificationDropdown.style.display =
      notificationDropdown.style.display === "block" ? "none" : "block";
  });

  document.addEventListener("click", function () {
    notificationDropdown.style.display = "none";
  });
});
