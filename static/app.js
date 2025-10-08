// Auto-submit with countdown support
(function () {
const el = document.getElementById("countdown");
if (!el) return;


let remaining = parseInt(el.getAttribute("data-remaining"), 10);
if (isNaN(remaining)) return;


function fmt(sec) {
const m = Math.floor(sec / 60);
const s = sec % 60;
return `${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
}


function tick() {
el.textContent = fmt(remaining);
if (remaining <= 0) {
const form = document.querySelector("form[action$='/submit']");
if (form) form.submit();
return;
}
remaining -= 1;
setTimeout(tick, 1000);
}


tick();
})();


// Convenience: press "S" to submit
document.addEventListener("keydown", (e) => {
if (e.key.toLowerCase() === "enter") {
const form = document.querySelector("form[action$='/submit']");
if (form) form.submit();
}
});