<!DOCTYPE html>
<html lang="en">
<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="icon" href="pafebackground.jpg"/>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.6/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-4Q6Gf2aSP4eDXB8Miphtr37CMZZQ5oXLH2yaXMJ2w8e2ZtHTl7GptT4jmndRuHDT" crossorigin="anonymous">

    <link rel="stylesheet" href="main.css">
    <script src="../node_modules/bootstrap/dist/js/bootstrap.bundle.min.js"></script>

<style>

@import url('https://fonts.googleapis.com/css2?family=Noto+Serif:ital,wght@0,100..900;1,100..900&family=Poppins:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;0,800;0,900;1,100;1,200;1,300;1,400;1,500;1,600;1,700;1,800;1,900&display=swap');

*{
    font-family: "Poppins", sans-serif;
    font-weight: 400;
    font-style: normal;
}
body{
    background: linear-gradient(135deg, rgba(57, 66, 77, 0.5) 30%, rgba(6, 73, 117, 0.9) 100%), url('pafebackground.jpg');
    background-size: cover;
    background-repeat: no-repeat;
    background-position: center;
}
.right-box{
    padding: 40px 30px 40px 30px;
}
.log-txt{
    color: #fff;
    font-size: 40px;
    font-weight: 700;
}
.welcome-txt{
    color: #fff;
    font-weight: 500;
}
::placeholder{
    font-size: 16px;
}
.log-btn-txt{
    font-weight: 700;
    background: linear-gradient(to right,rgb(105, 161, 194) 0%,rgb(26, 21, 123) 100%);
}

@media only screen and (max-width: 768px) {
    .box-area{
        margin: 0 10px;
    }
    .left-box {
        height: auto;
        padding: 20px;
        overflow: visible;
    }
    .right-box{
        padding: 20px;
    }
}
.error-message {
    min-height: 2em;
    width: 18rem;
    color: #fff;
    visibility: hidden;
    transition: visibility 0.3s ease;
}

.error-message.visible {
    background-color: #DC143C;
    visibility: visible;
}
.error-msg{
    margin-left: 1rem;
}


</style>

</head>
<body>
    
    <!-- MAIN CONTAINER -->

    <div class="container d-flex justify-content-center align-items-center min-vh-100">
    
    <!-- LOGIN CONTAINER -->

        <div class="row border rounded-5 p-3 bg-white shadow box-area">

    <!-- LEFT BOX -->

            <div class="col-md-6 d-flex justify-content-center align-items-center flex-column left-box">
                <div class="featured-image mb-3 text-center w-100">
                    <img src="pafenobg.png" alt="USG Logo" class="img-fluid" style="max-width: 250px; height: auto;">
                </div>
            </div>

    <!-- RIGHT BOX -->

            <div class="col-md-6 rounded-4 right-box" style="background: linear-gradient(140deg, rgba(33, 25, 72, 1) 25%, rgba(249, 166, 2, 1) 60%, rgba(187, 201, 189, 1) 80%);">
                <div class="row align-items-center">
                    <div class="header-text mb-4">
                        <h1 class="log-txt">LOG IN</h1>
                        <h5 class="welcome-txt">Welcome to Prime Association of Future Educators</h5>
                    </div>

                    <form id="loginForm" action="usg_login_verify.php" method="POST">
                        <div class="input-group mb-3">
                            <input type="text" id="userIdInput" name="userId" class="form-control form-control-lg bg-light fs-6" placeholder="User ID" required aria-label="User ID" />
                        </div>

                        <div class="input-group mb-3">
                            <input type="password" id="passwordInput" name="password" class="form-control form-control-lg bg-light fs-6" placeholder="Password" required aria-label="Password" />
                        </div>

                        <div class="input-group mb-5 d-flex">
                            <div class="form-check">
                                <input type="checkbox" class="form-check-input" id="rememberMe">
                                <label for="rememberMe" class="form-check-label text-light"><small>Remember Me</small></label>
                            </div>
                        </div>

                        <div class="input-group mb-3">
                            <button type="submit" id="loginBtn" class="btn btn-lg btn-primary w-100 fs-5 log-btn-txt">LOG IN</button>
                        </div>
                        <div id="loginError" class="error-message text-center"></div>
                    </form>

                </div>
            </div>
    
        </div>
    </div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    const userIdInput = document.getElementById('userIdInput');
    const passwordInput = document.getElementById('passwordInput');
    const rememberMe = document.getElementById('rememberMe');
    const loginBtn = document.getElementById('loginBtn');
    const loginError = document.getElementById('loginError');

    // Check for remembered user ID
    const rememberedUserId = localStorage.getItem('rememberedUserId');
    if (rememberedUserId) {
        userIdInput.value = rememberedUserId;
        rememberMe.checked = true;
    }

    loginForm.addEventListener('submit', function(e) {
        e.preventDefault();
        loginError.textContent = '';
        loginError.classList.remove('visible');

        // Remember me logic
        if (rememberMe.checked) {
            localStorage.setItem('rememberedUserId', userIdInput.value.trim());
        } else {
            localStorage.removeItem('rememberedUserId');
        }

        loginBtn.disabled = true;

        fetch('login_verify.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                userId: userIdInput.value.trim(),
                password: passwordInput.value.trim()
            })
        })
        .then(res => res.json())
        .then(data => {
            loginBtn.disabled = false;
            if (data.success) {
                if (data.role === 'officer') {
                    window.location.href = 'admin.php';
                } else {
                    window.location.href = 'student.php';
                }
            } else {
                loginError.textContent = data.message || 'Login failed. Please try again.';
                loginError.classList.add('visible');
            }
        })
        .catch(error => {
            loginBtn.disabled = false;
            loginError.textContent = 'A network error occurred. Please try again.';
            loginError.classList.add('visible');
        });
    });
});
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.6/dist/js/bootstrap.bundle.min.js" integrity="sha384-j1CDi7MgGQ12Z7Qab0qlWQ/Qqz24Gc6BM0thvEMVjHnfYGF0rmFCozFSxQBxwHKO" crossorigin="anonymous"></script>

</body>
</html>
