<?php
    include_once 'header.php';

    // 如果 Session 中没有用户 ID，说明已注销或未登录，严禁访问此页面
    if (!isset($_SESSION['u_id'])) {
        header("Location: index.php");
        exit(); 
    }
?>

<section class="main-container">
    <div class="main-wrapper">
        <h2>Change Password</h2>
        <br>
        
        <br>
        Please ensure your new password conforms to the complexity rules:
        <br>
        • Be at least 8 characters long<br>
        • Contain a mix of uppercase and lowercase<br>
        • Contain a digit<br>
        <form class="signup-form" action="includes/reset.inc.php" method="POST">
            <input type="password" name="old" value="" placeholder="Old Password" pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}" required>
            <input type="password" name="new" value="" placeholder="New Password" pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}" required>
            <input type="password" name="new_confirm" value="" placeholder="Confirm New Password" pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}" required>
            <button type="submit" name="reset" value="yes">Reset</button>
            <?php 
            //Generate CSRF token
            if (empty($_SESSION['csrf'])) {
                $_SESSION['csrf'] = bin2hex(random_bytes(32));
            }
            $token = $_SESSION['csrf'];
            ?>
            <input type="hidden" name="csrf-token" value="<?php echo $token ?>"/>
        </form>
    </div>
</section>

<?php
    include_once 'footer.php';
?>
