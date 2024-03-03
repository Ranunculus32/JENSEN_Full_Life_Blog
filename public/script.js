
const message = document.createElement("div");
message.classList.add("cookie-message");
message.textContent =
  "We use cookies for improved functionality and analytics.";
message.innerHTML =
  'We use cookies for improved functionality and analytics. <button class = "-btn btn--close-cookie" > Got it! </button> ';

//Delete element

document.querySelector(".btn--close--cookie");
addEventListener("click", function () {
  message.remove();
});
