$(document).on('click', '.course-for__det-top ', function (e) {
    if ($(this).parents('.answer__item').hasClass('active')) {
        // console.log(1)
        $(this).parents('.answer__item').removeClass('active');
        $(this).siblings('.course-for__det-hidden').hide(300);
    } else {
        $(this).parents('.course-for__detail-block').siblings().find('.answer__item').removeClass('active');
        $(this).parents('.course-for__detail-block').siblings().find('.course-for__det-hidden').slideUp();
        $(this).parents('.answer__item').addClass('active');
        $(this).siblings('.course-for__det-hidden').show(300);
    }
});

var hideBlocks = document.querySelectorAll('.course-for__detail-block-not-visible')
document.querySelector('.jc-course-for__open-more').addEventListener('click', function () {
    this.classList.toggle('active')
    for (item of hideBlocks) {
        item.classList.toggle('active')
    }
})

$(document).on('click', '.get-to-know__top-item', function (e) {
    if ($(this).parents('.js-get-to-know__point').hasClass('active')) {
        // console.log(1)
        $(this).parents('.js-get-to-know__point').removeClass('active');
        $(this).siblings('.get-to-know__hide-block').hide(300);
    } else {
        // console.log(2)
        $(this).parents('.js-get-to-know__point').siblings().removeClass('active');
        $(this).parents('.js-get-to-know__point').siblings().find('.get-to-know__hide-block').slideUp();
        $(this).parents('.js-get-to-know__point').addClass('active');
        $(this).siblings('.get-to-know__hide-block').show(300);
    }
});


// var openHide2 = document.querySelectorAll('.get-to-know__point-hide');
// document.querySelector('.js-get-to-know__open-more').addEventListener('click', function () {
//     this.classList.toggle('active')
//     document.querySelector('.js-get-to-know__hide-whole-block').classList.toggle('active')
// })

if ($(window).width() < 769) {
    $(document).on('click', '.course-works__title', function (e) {
        if ($(this).parents('.course-works__info-flex').hasClass('active')) {
            // console.log(1)
            $(this).parents('.course-works__info-flex').removeClass('active');
            $(this).siblings('.course-works__text').hide(300);
        } else {
            // console.log(2)
            $(this).parents('.course-works__info-flex').siblings().removeClass('active');
            $(this).parents('.course-works__info-flex').siblings().find('.course-works__text').slideUp();
            $(this).parents('.course-works__info-flex').addClass('active');
            $(this).siblings('.course-works__text').show(300);
        }
    });
}
var swiper1 = new Swiper(".mentorsSwiper", {
    slidesPerView: 'auto',
    spaceBetween: 80,
    speed: 1000,
    mousewheel: true,
    keyboard: true,
    breakpoints: {
        100: {
            spaceBetween: 20,
        },
        769: {
            spaceBetween: 30,
        },
        992: {
            spaceBetween: 45,
        },
        1201: {
            spaceBetween: 80,
        }

    }
});

if ($(window).width() < 769) {

    $(document).on('click', '.faq__question', function (e) {
        if ($(this).parents('.faq__flex').hasClass('active')) {
            // console.log(1)
            $(this).parents('.faq__flex').removeClass('active');
            $(this).siblings('.faq__ask').slideUp();
        } else {
            // console.log(2)
            $(this).parents('.faq__flex').siblings().removeClass('active');
            $(this).parents('.faq__flex').siblings().find('.faq__ask').slideUp();
            $(this).parents('.faq__flex').addClass('active');
            $(this).siblings('.faq__ask').slideDown();
        }
    });
}
AOS.init({
    duration: 1500,
    once: true,
});
if ($(window).width() < 769) {
    AOS.init({
        once: true,
    });

}


$("#second").inputmask("+55 (99) 99999-9999");

if ($(window).width() > 769) {
    $(".faq__flex").hover(function () {
        $(this).find('.faq__ask').show();
        console.log(1)
    }, function () {
        $(this).find('.faq__ask').hide();
        console.log(2)
    });
}
// if ($(window).width() > 769){
//     $('.faq__question').mouseover(function(){
//         if($(this).hasClass(''))
//         $('.faq__ask').css({
//             'opacity':'1', 'visibility':'visible'
//         });
//     })
// }
$(document).ready(function(){
    $("#fixed").on("click","a", function (event) {
        event.preventDefault();
        var id  = $(this).attr('href'),
        top = $(id).offset().top;
        $('body,html').animate({scrollTop: top}, 1500);
    });
});