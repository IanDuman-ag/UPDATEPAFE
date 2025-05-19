<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
include_once 'connection.php';
header('Content-Type: application/json');

if ($con->connect_error) {
    echo json_encode(['success' => false, 'message' => 'Database connection failed: ' . $con->connect_error]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);

    if (!$data) {
        echo json_encode(['success' => false, 'message' => 'No data received']);
        exit;
    }

    $userId = trim($data['userId']);
    $password = trim($data['password']);

    $stmt = $con->prepare("SELECT * FROM pafe_user WHERE user_id = ?");
    $stmt->bind_param("s", $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result && $result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $storedPassword = $user['password'];

        // Check if the stored password is hashed (starts with $2y$ for bcrypt)
        if (
            (strlen($storedPassword) === 60 && str_starts_with($storedPassword, '$2y$')) &&
            password_verify($password, $storedPassword)
        ) {
            // Hashed password and verified
            loginSuccess($user);
        } elseif ($password === $storedPassword) {
            // Plain-text password match
            // Migrate to hashed password
            $newHash = password_hash($password, PASSWORD_DEFAULT);
            $update = $con->prepare("UPDATE pafe_user SET password = ? WHERE user_id = ?");
            $update->bind_param("ss", $newHash, $userId);
            $update->execute();
            $update->close();

            loginSuccess($user);
        } else {
            echo json_encode(['success' => false, 'message' => 'Invalid password']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'User not found']);
    }

    $stmt->close();
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
}

$con->close();

function loginSuccess($user) {
    $_SESSION['user_id'] = $user['user_id'];
    $_SESSION['role'] = $user['role'];
    $_SESSION['logged_in'] = true;

    // Fetch user's full name from user_profile table
    global $con;
    $stmt = $con->prepare("SELECT full_name FROM pafe_user_profile WHERE user_id = ?");
    $stmt->bind_param("s", $user['user_id']);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($profile = $result->fetch_assoc()) {
        $_SESSION['user_name'] = $profile['full_name'];
    } else {
        $_SESSION['user_name'] = $user['user_id']; // Fallback to user_id if no profile found
    }
    $stmt->close();

    echo json_encode([
        'success' => true,
        'message' => 'Login successful',
        'role' => $user['role']
    ]);
}
?>
