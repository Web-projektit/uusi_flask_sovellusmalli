let sahkoposti = document.querySelector('#email');
let pituus = document.querySelector('#pituus');

sahkoposti.addEventListener('input', () => {
    console.log(sahkoposti.value.length)
    pituus.innerHTML = sahkoposti.value.length
    })