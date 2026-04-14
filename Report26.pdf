<?php

    if (isset($_POST['submit'])) {

        session_start();
        include_once 'dbh.inc.php';

        $uid = $_POST['uid'];
        $pwd = $_POST['pwd'];

        if(!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ipAddr=$_SERVER['HTTP_CLIENT_IP'];
        } elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ipAddr=$_SERVER['HTTP_X_FORWARDED_FOR'];
        }
          else {
            $ipAddr=$_SERVER['REMOTE_ADDR'];
        }

        $time = date("Y-m-d H:i:s");
        //CHECK IF USER IS LOCKED OUT
        $checkClient = "SELECT `failedLoginCount`, `timeStamp` FROM `failedLogins` WHERE `ip` = ?";
        $stmt = $conn->prepare($checkClient);
        $stmt->bind_param("s", $ipAddr);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 0) {
            $initialiseIP = "INSERT INTO `failedLogins` (`ip`, `timeStamp`, `failedLoginCount`, `lockOutCount`) VALUES (?, ?, 0, 0)";
            $stmtInit = $conn->prepare($initialiseIP);
            $stmtInit->bind_param("ss", $ipAddr, $time);
            $stmtInit->execute();
            $failedCount = 0;
            $lastTime = $time;
        } else {
            $row = $result->fetch_assoc();
            $failedCount = $row['failedLoginCount'];
            $lastTime = $row['timeStamp'];
        }

        //锁定时间
        $lockoutDuration = 180;
        if ($failedCount >= 5) {
            $currentTime = time();
            $lastFailureTime = strtotime($lastTime);
            $secondsPassed = $currentTime - $lastFailureTime;

            if ($secondsPassed < $lockoutDuration) {
                $_SESSION['register'] = "Error: Too many attempts. Locked out for " . ($lockoutDuration - $secondsPassed) . " seconds.";
                header("Location: ../index.php");
                exit();
            } else {
                $resetForRetry = "UPDATE `failedLogins` SET `failedLoginCount` = 0 WHERE `ip` = ?";
                $stmtReset = $conn->prepare($resetForRetry);
                $stmtReset->bind_param("s", $ipAddr);
                $stmtReset->execute();
                $failedCount = 0;
            }
        }
        
        // Check for empty fields
        if (empty($uid) || empty($pwd)) {
            //增加失败计数
            $updateCount = "UPDATE `failedLogins` SET `failedLoginCount` = `failedLoginCount` + 1, `timeStamp` = ? WHERE `ip` = ?";
            $stmt = $conn->prepare($updateCount);
            $stmt->bind_param("ss", $time, $ipAddr);
            $stmt->execute();

            $_SESSION['register'] = "Cannot submit empty username or password.";
            header("Location: ../index.php");
            exit();

        } else {

            //Check to make sure only alphabetical characters are used for the username
            if (!preg_match("/^[a-zA-Z]*$/", $uid)) {
                //增加失败计数
                $updateCount = "UPDATE `failedLogins` SET `failedLoginCount` = `failedLoginCount` + 1, `timeStamp` = ? WHERE `ip` = ?";
                $stmt = $conn->prepare($updateCount);
                $stmt->bind_param("ss", $time, $ipAddr);
                $stmt->execute();

                $_SESSION['register'] = "Username must only contain alphabetic characters.";
                header("Location: ../index.php");
                exit();

            } else {
				
                    $sql = "SELECT * FROM `sapusers` WHERE `user_uid` = ?"; //$uid
                    $stmt = $conn->prepare($sql);
                    $stmt->bind_param("s", $uid);
                    $stmt->execute();
                    $result = $stmt->get_result();

					//If the user already exists, prevent them from signing up
                    if ($result->num_rows > 0) {
                        //增加失败计数
                        $updateCount = "UPDATE `failedLogins` SET `failedLoginCount` = `failedLoginCount` + 1, `timeStamp` = ? WHERE `ip` = ?";
                        $stmt = $conn->prepare($updateCount);
                        $stmt->bind_param("ss", $time, $ipAddr);
                        $stmt->execute();

                        $_SESSION['register'] = "Error.";
                        header("Location: ../index.php");
                        exit();

                    } else {
                        //如果用户不存在，则创建新用户并HASH加密存入数据库
                        //$hashedPWD = $pwd;
                        $hashedPWD = password_hash($pwd, PASSWORD_DEFAULT);

                        $sql = "INSERT INTO `sapusers` (`user_uid`, `user_pwd`) VALUES (?, ?)"; 
                        $stmt = $conn->prepare($sql);
                        $stmt->bind_param("ss", $uid, $hashedPWD);
                        
                        if(!$stmt->execute()) {
                            echo "Error: " . $stmt->error;
                        }
                        
                        $resetCount = "UPDATE `failedLogins` SET `failedLoginCount` = 0 WHERE `ip` = ?";
                        $stmtReset = $conn->prepare($resetCount);
                        $stmtReset->bind_param("s", $ipAddr);
                        $stmtReset->execute();

                        $_SESSION['register'] = "You've successfully registered as " . $uid . ".";

                        header("Location: ../index.php");
                        exit();

                    }
                }   
        }
    }