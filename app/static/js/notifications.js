document.addEventListener("DOMContentLoaded", function () {
  const notificationIcon = document.getElementById("notification-icon");
  const notificationDropdown = document.getElementById("notification-dropdown");

  notificationIcon.addEventListener("click", function (event) {
    event.stopPropagation();
    notificationDropdown.style.display =
      notificationDropdown.style.display === "block" ? "none" : "block";
    
    // Fetch notifications dynamically
    fetchNotifications();
  });

  document.addEventListener("click", function () {
    notificationDropdown.style.display = "none";
  });

  function fetchNotifications() {
    fetch("/get_notifications")
      .then(response => response.json())
      .then(data => {
        const notificationList = document.getElementById("notification-list");
        notificationList.innerHTML = ""; // Clear current list
        data.notifications.forEach(notification => {
          const listItem = document.createElement("li");
          listItem.textContent = notification.message;
          notificationList.appendChild(listItem);
        });
      });
  }
});
