/* bcnet.js: Javascript code for the Claim Account servlet page. Requires jQuery
 * Author: Steve Hillman <hillman@sfu.ca>
 */

 crowdForgotForm = "/crowd/console/forgottenlogindetails!default.action";

$(function() {
	// Set up listners on each choiceBox div
	$("#claim-choiceBox").click(function() {
		$("#new-inputBox").hide(0);
		$("#forgot-inputBox").hide(0);
		$("#claim-inputBox").fadeIn(500);
		if (timeout) { clearTimeout(timeout);}
	});

	$("#new-choiceBox").click(function() {
		$("#claim-inputBox").hide(0);
		$("#forgot-inputBox").hide(0);
		$("#new-inputBox").fadeIn(500);
		if (timeout) { clearTimeout(timeout);}
	});
	$("#forgot-choiceBox").click(function() {
		$("#new-inputBox").hide(0);
		$("#claim-inputBox").hide(0);
		$("#forgot-inputBox").fadeIn(500);
		downCounter(5);
	});

	// Enable fancy Tool Tips
	$(document).tooltip();

	// grey the choiceBox we're hovering over
	$(".choiceBox").hover(function() {
		$(this).css("background-color","LightGrey")
	}, function() {
		$(this).css("background-color","White")
	});

	// show/hide optional Password fields
	$("#setPassword").click(function() {
		if ($(this).is(':checked')) {
			$(".optionalPassword").fadeIn(500)
		} else {
			$(".optionalPassword").fadeOut(500)
		}
	});

	// Stylize our buttons and input fields
	$(".buttons").button();
	$('input').addClass("ui-widget ui-widget-content ui-corner-all");

	// add form validation
	$("#newUserForm").validate({ 
		rules: {
			firstname: "required",
			lastname: "required",
			email: {
				required: true,
				email: true,
			},
    		newUsername: {
      			required: true,
      			remote: "claimAccount?action=checkUser",
      			
    		},
    		password: {
				required: "#setPassword:checked",
				minlength: 8,
			},
			password2: {
				required: "#setPassword:checked",
				equalTo: "#password",
  			},
  		},
  		messages: {
  			password: {
				required: "Required input",
				minlength: jQuery.validator.format("At least {0} characters are necessary")
  			},
  			password2: {
				required: "Required input",
				equalTo: "Passwords must match"
  			}
  		},
  		errorClass: "inputError"
  	});

	// Catch changes to First/LastName fields and try to generate username
	$("#firstname").change(genUsername);
	$("#lastname").change(genUsername);
});

var timeout;

function downCounter(start) {
	var count = $("#countdown");
	if (start) {
		count.text(start);
	} else {
		var currentCount = count.text();
		if (currentCount == 1) {
			window.location.href = crowdForgotForm;
			return;
		}
		count.text(currentCount - 1);
	}
	count.css({opacity:1});
	count.animate({opacity:0},750);
	timeout = setTimeout(downCounter,1000);
}


function genUsername() {
	
	// grab first/lastname and remove non alpha chars
	fn = $("#firstname").val();
	ln = $("#lastname").val();
	console.log("genUsername called with " + fn + " " + ln);
	if (fn && fn.length) {
		fn.replace(/[^A-Za-z]/gi, '');
	}
	if (ln && ln.length) {
		ln.replace(/[^A-Za-z]/gi, '');
	}

    var uname = "";
	if (fn && fn.length && ln && ln.length) {
	    uname = fn.substring(0,1);
	    uname = uname + ln.substring(0,7);
	    uname = uname.toLowerCase();
	} else if (fn && fn.length) {
		uname = fn.substring(0,8);
	}

    $("#newUsername").val(uname);
}

