<?php

//If user is not logged in or requesting to reset, redirect
include 'dbh.inc.php';
session_start();
//改为POST提交
if (!isset($_POST['reset'],$_SESSION['u_uid'])) {
    $_SESSION['resetError'] = "Error code 1";
    header("Location: ../index.php");
} else {
    // 校验 CSRF Token
    if (!isset($_POST['csrf-token']) || $_POST['csrf-token'] !== $_SESSION['csrf']) {
            $_SESSION['resetError'] = "Security Validation Failed (CSRF)!";
            header("Location: ../index.php");
            exit();
    }

    $oldpass = $_POST['old'];
    $newConfirm = $_POST['new_confirm'];
    $newpass = $_POST['new'];

    if (empty($oldpass) || empty($newpass)) {
        $_SESSION['resetError'] = "Error code 2";
    } else {
        
        $uid = $_SESSION['u_uid'];

        $checkOld = "SELECT * FROM `sapusers` WHERE `user_uid` = ?"; //$uid
        $stmt = $conn->prepare($checkOld);
        $stmt->bind_param("s", $uid);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) { 

            $row = mysqli_fetch_assoc($result); 

			//更改密码验证逻辑，hash密码验证
            if (!password_verify($oldpass, $row['user_pwd'])) {
                $_SESSION['resetError'] = "Error code 4";
                header("Location: ../index.php");
                exit();
            } else {
                if ($newConfirm == $newpass) { //confirm they match

                    //对新密码进行hash加密
                    $newHashedPwd = password_hash($newpass, PASSWORD_DEFAULT);

                    $changePass = "UPDATE `sapusers` SET `user_pwd` = ? WHERE `user_uid` = ?"; //$newpass, $uid
                    $stmt = $conn->prepare($changePass);
                    $stmt->bind_param("ss", $newHashedPwd, $uid);
                            
                    if(!$stmt->execute()) {
                        echo "Error: " . $stmt->error;
                    }

                    header("Location: ./logout.inc.php");
                    exit();
                } else {
                    $_SESSION['resetError'] = "Error code 5";
                    header("Location: ../index.php");
                    exit();
                }
            }
        } else {
            $_SESSION['resetError'] = "Error code 6"; 
            header("Location: ../index.php");
            exit();
        }
    }
}