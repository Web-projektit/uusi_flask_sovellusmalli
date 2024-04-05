//moment.tz.setDefault("Europe/Helsinki")

    const navbarToggler = document.querySelector('.navbar-toggler');
    navbarToggler.addEventListener('click', (event) => {
        //console.log(navbarToggler.getAttribute('aria-expanded'))
        if (navbarToggler.getAttribute('aria-expanded') === 'true') {
          navbarToggler.innerHTML = '<i class="fa fa-times"></i>';
        } else {
          navbarToggler.innerHTML = '<i class="fa fa-bars"></i>';
        }
    });


const poista_is_invalid = event => {
    let element = event.target;
    if (element.classList.contains('is-invalid')){
      element.classList.remove("is-invalid");    
      element.removeEventListener("input", poista_is_invalid);
      }
    }  
  
/* 
document.addEventListener('DOMContentLoaded', () => {});
*/  
  
(() => {
    'use strict'
    /* Quick_form lisää palvelimen validointivirheestä has-danger-classin ja invalid-feedback-elementin, 
        joka näkyy, jos form-control-classiin lisätään is-invalid ja häipyy, kun is-invalid poistetaan. */
    /*document.querySelectorAll(".has-danger .form-control").forEach(
        element => {
            element.classList.add('is-invalid');
            element.addEventListener("input", poista_is_invalid)
            }
          )*/

    document.querySelectorAll(".is-invalid,:invalid").forEach(
      element => element.addEventListener("input", poista_is_invalid)
      )
    

    const forms = document.querySelectorAll('.needs-validation')
    // Loop over them and prevent submission
    Array.from(forms).forEach(form => {
      form.addEventListener('submit', event => {
        if (!form.checkValidity()) {
          event.preventDefault()
          event.stopPropagation()     
          /* 
          Palvelimen lomakekäsittelyn jälkeen validointi palautetaan selaimelle lomaketta
          lähetettäessä. Tällöin selaimen oma validointiviesti asetetaan 
          .invalid-feedback-elementteihin. Huom. invalid-feedback-elementin tulee tässä olla 
          virheellisen elementin sibling. Validointiviesti päivitetään onblur-tapahtumasta. 
          Jos kentän arvo ei läpäise selainvalidointia, selain asettaa kentän :invalid-tilaan,
          jolloin Bootstrap tuo .invalid-feedback-elementin näkyviin, ja tekstinä näkyy näin
          selaimen oma validointivirhetyyppikohtainen validointiviesti (selaimen kielellä). 
          */
          /* Quick_form ei lisää Selaimen validointivirheestä invalid-feedback-elementtiä,
             joten se lisätään, jos selain asettaa kentän :invalid-tilaan eikä sitä ole
             lisätty ennestään. */ 
          document.querySelectorAll("input:invalid")
          .forEach(element => {
            console.log(element.name+':'+element.validationMessage)
            /* Tätä ei tarvita, jos quick_form lisää invalid-feedback-elementin
              if (!element.nextElementSibling){
                let feedback = document.createElement('div')
                feedback.classList.add('invalid-feedback')
                element.parentElement.appendChild(feedback)
                } */
            /* Tämä tarvitaan näyttämään mahdollinen omakin validointiviesti,
               esim. salasana ei täsmää. */
            element.nextElementSibling.innerHTML = element.validationMessage
            /*
              Tätä ei todennäköisesti tarvita, ajatuksena on palauttaa selaimen oma validointiviesti,
              mutta oma tarkistus on jo saattanut asettaa elementin :valid-tilaan.   
            */
              element.addEventListener('input', () => 
              element.nextElementSibling.innerHTML = element.validationMessage)
              
            })    
          }
        form.classList.add('was-validated')
        }, false)
      })
    })()   
  