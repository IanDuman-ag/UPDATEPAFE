<?php
session_start();
$_SESSION['user_name'] = isset($_SESSION['user_name']) ? $_SESSION['user_name'] : "J";

// Enable error reporting for debugging, but log to a file
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', 'logs/php_errors.log');
error_reporting(E_ALL);

// Database connection
$host = "localhost";
$username = "root";
$password = "";
$dbname = "dbpafe";

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    error_log("Connection failed: " . $e->getMessage());
    http_response_code(500);
    exit("Database connection failed. Please try again later.");
}

// Create uploads directory if it doesn't exist
$upload_dir = 'uploads/';
if (!is_dir($upload_dir)) {
    mkdir($upload_dir, 0755, true);
}

// Handle profile update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_profile') {
    $full_name = trim($_POST['full_name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $user_id = $_SESSION['user_id'] ?? '';

    if (empty($full_name) || empty($email) || empty($user_id)) {
        header("Location: ?page=home&error=Full name and email are required.");
        exit;
    }

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        header("Location: ?page=home&error=Invalid email format.");
        exit;
    }

    // Check if email is already used by another user
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM pafe_user_profile WHERE email = ? AND user_id != ?");
    $stmt->execute([$email, $user_id]);
    if ($stmt->fetchColumn() > 0) {
        header("Location: ?page=home&error=Email is already in use.");
        exit;
    }

    $profile_picture = $_SESSION['profile_picture'] ?? 'default.png';
    $upload_dir = 'Uploads/profile_pictures/';
    $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
    $max_size = 2 * 1024 * 1024; // 2MB

    if (!empty($_FILES['profile_picture']['name'])) {
        $file = $_FILES['profile_picture'];
        if ($file['error'] === UPLOAD_ERR_OK) {
            if (in_array($file['type'], $allowed_types) && $file['size'] <= $max_size) {
                $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
                $filename = uniqid() . '.' . $ext;
                $destination = $upload_dir . $filename;

                if (move_uploaded_file($file['tmp_name'], $destination)) {
                    // Delete old profile picture if it exists and is not default
                    if ($profile_picture !== 'default.png' && file_exists($upload_dir . $profile_picture)) {
                        unlink($upload_dir . $profile_picture);
                    }
                    $profile_picture = $filename;
                } else {
                    header("Location: ?page=home&error=Failed to upload profile picture.");
                    exit;
                }
            } else {
                header("Location: ?page=home&error=Invalid file type or size exceeds 2MB.");
                exit;
            }
        } else {
            header("Location: ?page=home&error=Error uploading file.");
            exit;
        }
    }

    // Update or insert user profile
    $stmt = $pdo->prepare("
        INSERT INTO pafe_user_profile (user_id, full_name, email, profile_picture, gender, year_level, section_name)
        VALUES (?, ?, ?, ?, NULL, NULL, NULL)
        ON DUPLICATE KEY UPDATE
            full_name = VALUES(full_name),
            email = VALUES(email),
            profile_picture = VALUES(profile_picture)
    ");
    $stmt->execute([$user_id, $full_name, $email, $profile_picture]);

    // Update session variables
    $_SESSION['user_name'] = $full_name;
    $_SESSION['email'] = $email;
    $_SESSION['profile_picture'] = $profile_picture;

    header("Location: ?page=home&success=Profile updated successfully.");
    exit;
}

// Fetch user profile information
try {
    if (isset($_SESSION['user_id'])) {
        $stmt = $pdo->prepare("SELECT full_name, email, profile_picture FROM pafe_user_profile WHERE user_id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $user_profile = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user_profile) {
            $_SESSION['user_name'] = $user_profile['full_name'];
            $_SESSION['email'] = $user_profile['email'];
            $_SESSION['profile_picture'] = $user_profile['profile_picture'] ?? 'default.png';
        }
    }
} catch (PDOException $e) {
    error_log("Error fetching user profile: " . $e->getMessage());
}

// Function to update event statuses
function updateEventStatuses($pdo) {
    try {
        $current_time = date('Y-m-d H:i:s');
        $stmt = $pdo->prepare("
            UPDATE pafe_events
            SET status = CASE
                WHEN status = 'Canceled' THEN 'Canceled'
                WHEN CONCAT(event_date, ' ', event_time) > ? THEN 'Scheduled'
                WHEN CONCAT(event_date, ' ', event_time) <= ? 
                    AND DATE_ADD(CONCAT(event_date, ' ', event_time), INTERVAL 2 HOUR) >= ? THEN 'Ongoing'
                ELSE 'Completed'
            END
            WHERE status != 'Canceled'
        ");
        $stmt->execute([$current_time, $current_time, $current_time]);
    } catch (PDOException $e) {
        error_log("Error updating event statuses: " . $e->getMessage());
    }
}

// Handle report generation as CSV
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'generate_report') {
    $report_type = $_POST['report_type'] ?? '';
    
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $report_type . '_report.csv"');

    // Create a file pointer connected to the output stream
    $output = fopen('php://output', 'w');

    // Write UTF-8 BOM for Excel compatibility
    fwrite($output, "\xEF\xBB\xBF");

    try {
        if ($report_type === 'events') {
            fputcsv($output, ['Event Name', 'Date', 'Time', 'Status', 'Description', 'Created At']);
            $stmt = $pdo->query("SELECT * FROM pafe_events ORDER BY event_date, event_time");
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($data as $row) {
                fputcsv($output, [
                    $row['event_name'] ?? '',
                    $row['event_date'] ?? '',
                    $row['event_time'] ?? '',
                    $row['status'] ?? '',
                    $row['description'] ?? '',
                    $row['created_at'] ?? ''
                ]);
            }
        } elseif ($report_type === 'attendance') {
            fputcsv($output, ['Full Name', 'Event', 'Gender', 'Year Level', 'Section', 'Status', 'Created At']);
            $stmt = $pdo->query("SELECT a.*, e.event_name FROM pafe_attendance a LEFT JOIN pafe_events e ON a.event_id = e.id ORDER BY a.fullname");
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($data as $row) {
                fputcsv($output, [
                    $row['fullname'] ?? '',
                    $row['event_name'] ?? 'No Event',
                    $row['gender'] ?? '',
                    $row['year_level'] ?? '',
                    $row['section'] ?? '',
                    $row['status'] ?? '',
                    $row['created_at'] ?? ''
                ]);
            }
        } elseif ($report_type === 'feedback') {
            fputcsv($output, ['Event', 'User', 'Comment', 'Rating', 'Created At']);
            $stmt = $pdo->query("SELECT f.*, e.event_name FROM pafe_feedback f LEFT JOIN pafe_events e ON f.event_id = e.id ORDER BY f.created_at DESC");
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($data as $row) {
                fputcsv($output, [
                    $row['event_name'] ?? '',
                    $row['user_name'] ?? '',
                    $row['comment'] ?? '',
                    $row['rating'] ?? '',
                    $row['created_at'] ?? ''
                ]);
            }
        }
    } catch (PDOException $e) {
        error_log("Error generating report: " . $e->getMessage());
    }

    fclose($output);
    exit;
}

// Handle CRUD operations
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'];
    
    try {
        // Event CRUD
        if ($action === 'create_event' || $action === 'update_event') {
            $event_name = trim($_POST['event_name'] ?? '');
            $event_date = $_POST['event_date'] ?? '';
            $event_time = $_POST['event_time'] ?? '';
            $status = $_POST['status'] ?? '';
            $description = trim($_POST['description'] ?? '');

            if (empty($event_name) || empty($event_date) || empty($event_time) || empty($status)) {
                header("Location: ?page=events&error=All fields except description are required.");
                exit;
            }

            if ($action === 'create_event') {
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM pafe_events WHERE event_name = ? AND event_date = ? AND event_time = ?");
                $stmt->execute([$event_name, $event_date, $event_time]);
                if ($stmt->fetchColumn() > 0) {
                    header("Location: ?page=events&error=An event with the same name, date, and time already exists.");
                    exit;
                } else {
                    $stmt = $pdo->prepare("INSERT INTO pafe_events (event_name, event_date, event_time, status, description) VALUES (?, ?, ?, ?, ?)");
                    $stmt->execute([$event_name, $event_date, $event_time, $status, $description]);
                    updateEventStatuses($pdo);
                    header("Location: ?page=events&success=Event created successfully.");
                    exit;
                }
            } elseif ($action === 'update_event') {
                $id = $_POST['event_id'] ?? '';
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM pafe_events WHERE event_name = ? AND event_date = ? AND event_time = ? AND id != ?");
                $stmt->execute([$event_name, $event_date, $event_time, $id]);
                if ($stmt->fetchColumn() > 0) {
                    header("Location: ?page=events&error=An event with the same name, date, and time already exists.");
                    exit;
                } else {
                    $stmt = $pdo->prepare("UPDATE pafe_events SET event_name = ?, event_date = ?, event_time = ?, status = ?, description = ? WHERE id = ?");
                    $stmt->execute([$event_name, $event_date, $event_time, $status, $description, $id]);
                    updateEventStatuses($pdo);
                    header("Location: ?page=events&success=Event updated successfully.");
                    exit;
                }
            }
        }
        
        // Delete Event
        if ($action === 'delete_event') {
            $id = $_POST['event_id'] ?? '';
            $stmt = $pdo->prepare("DELETE FROM pafe_events WHERE id = ?");
            $stmt->execute([$id]);
            header("Location: ?page=events&success=Event deleted successfully.");
            exit;
        }

        // Attendance CRUD
        if ($action === 'create_attendance' || $action === 'update_attendance') {
            $fullname = trim($_POST['fullname'] ?? '');
            $gender = $_POST['gender'] ?? '';
            $year_level = trim($_POST['year_level'] ?? '');
            $section = trim($_POST['section'] ?? '');
            $status = $_POST['status'] ?? '';
            $event_id = $_POST['event_id'] ?? '';

            if (empty($fullname) || empty($gender) || empty($year_level) || empty($section) || empty($status) || empty($event_id)) {
                header("Location: ?page=attendance&error=All fields are required.");
                exit;
            }

            if ($action === 'create_attendance') {
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM pafe_attendance WHERE fullname = ? AND section = ? AND event_id = ?");
                $stmt->execute([$fullname, $section, $event_id]);
                if ($stmt->fetchColumn() > 0) {
                    header("Location: ?page=attendance&error=An attendance record for this person in this section for this event already exists.");
                    exit;
                } else {
                    $stmt = $pdo->prepare("INSERT INTO pafe_attendance (fullname, gender, year_level, section, status, event_id) VALUES (?, ?, ?, ?, ?, ?)");
                    $stmt->execute([$fullname, $gender, $year_level, $section, $status, $event_id]);
                    header("Location: ?page=attendance&success=Attendance record created successfully.");
                    exit;
                }
            } elseif ($action === 'update_attendance') {
                $id = $_POST['attendance_id'] ?? '';
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM pafe_attendance WHERE fullname = ? AND section = ? AND event_id = ? AND id != ?");
                $stmt->execute([$fullname, $section, $event_id, $id]);
                if ($stmt->fetchColumn() > 0) {
                    header("Location: ?page=attendance&error=An attendance record for this person in this section for this event already exists.");
                    exit;
                } else {
                    $stmt = $pdo->prepare("UPDATE pafe_attendance SET fullname = ?, gender = ?, year_level = ?, section = ?, status = ?, event_id = ? WHERE id = ?");
                    $stmt->execute([$fullname, $gender, $year_level, $section, $status, $event_id, $id]);
                    header("Location: ?page=attendance&success=Attendance record updated successfully.");
                    exit;
                }
            }
        }

        // Delete Attendance
        if ($action === 'delete_attendance') {
            $id = $_POST['attendance_id'] ?? '';
            $stmt = $pdo->prepare("DELETE FROM pafe_attendance WHERE id = ?");
            $stmt->execute([$id]);
            header("Location: ?page=attendance&success=Attendance record deleted successfully.");
            exit;
        }

        // Handle attendance approval/rejection
        if ($action === 'approve_attendance') {
            $id = filter_var($_POST['attendance_id'] ?? '', FILTER_VALIDATE_INT);
            if (!$id) {
                header("Location: ?page=attendance&error=Invalid attendance ID.");
                exit;
            }
            $stmt = $pdo->prepare("UPDATE pafe_attendance SET status = 'Approved' WHERE id = ?");
            $stmt->execute([$id]);
            header("Location: ?page=attendance&success=Attendance approved successfully.");
            exit;
        }

        if ($action === 'reject_attendance') {
            $id = filter_var($_POST['attendance_id'] ?? '', FILTER_VALIDATE_INT);
            if (!$id) {
                header("Location: ?page=attendance&error=Invalid attendance ID.");
                exit;
            }
            $stmt = $pdo->prepare("UPDATE pafe_attendance SET status = 'Rejected' WHERE id = ?");
            $stmt->execute([$id]);
            header("Location: ?page=attendance&success=Attendance rejected successfully.");
            exit;
        }

        // Delete Feedback
        if ($action === 'delete_feedback') {
            $feedback_id = filter_var($_POST['feedback_id'] ?? '', FILTER_VALIDATE_INT);
            
            if (!$feedback_id) {
                if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
                    echo json_encode(['error' => 'Invalid feedback ID']);
                    exit;
                }
                header("Location: ?page=feedback&error=Invalid feedback ID.");
                exit;
            }

            $stmt = $pdo->prepare("DELETE FROM pafe_feedback WHERE id = ?");
            $stmt->execute([$feedback_id]);

            // Get updated feedback count
            $stmt = $pdo->query("SELECT COUNT(*) FROM pafe_feedback");
            $new_total_feedback = $stmt->fetchColumn();

            if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
                echo json_encode([
                    'success' => true,
                    'new_count' => $new_total_feedback,
                    'message' => 'Feedback deleted successfully'
                ]);
                exit;
            }

            header("Location: ?page=feedback&success=Feedback deleted successfully.");
            exit;
        }
    } catch (PDOException $e) {
        error_log("Error in CRUD operation: " . $e->getMessage());
        header("Location: ?page=" . ($_GET['page'] ?? 'home') . "&error=An error occurred. Please try again.");
        exit;
    }
}

// Fetch counts for Home section
try {
    $stmt = $pdo->query("SELECT COUNT(*) FROM pafe_events");
    $total_events = $stmt->fetchColumn();

    $stmt = $pdo->query("SELECT COUNT(*) FROM pafe_feedback");
    $total_feedback = $stmt->fetchColumn();

    $stmt = $pdo->query("SELECT COUNT(*) FROM pafe_attendance");
    $total_attendance = $stmt->fetchColumn();
} catch (PDOException $e) {
    $total_events = 0;
    $total_feedback = 0;
    $total_attendance = 0;
    error_log("Error fetching counts: " . $e->getMessage());
}

// Update event statuses
updateEventStatuses($pdo);

// Fetch all events
try {
    $stmt = $pdo->query("SELECT * FROM pafe_events ORDER BY event_date, event_time");
    $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $events = [];
    error_log("Error fetching events: " . $e->getMessage());
}

// Fetch all attendance records with event names
try {
    $stmt = $pdo->query("
        SELECT a.*, e.event_name, e.event_date, e.event_time 
        FROM pafe_attendance a 
        LEFT JOIN pafe_events e ON a.event_id = e.id 
        ORDER BY a.created_at DESC
    ");
    $attendances = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Calculate statistics
    $total_count = count($attendances);
    $pending_count = count(array_filter($attendances, function($a) { 
        return strtolower($a['status']) === 'pending'; 
    }));
    $approved_count = count(array_filter($attendances, function($a) { 
        return strtolower($a['status']) === 'approved'; 
    }));
} catch (PDOException $e) {
    $attendances = [];
    $total_count = 0;
    $pending_count = 0;
    $approved_count = 0;
    error_log("Error fetching attendance: " . $e->getMessage());
}

// Fetch feedback records for all users for the selected event
$feedbacks = [];
$selected_event_id = isset($_GET['event_id']) ? (int)$_GET['event_id'] : null;
if ($selected_event_id) {
    try {
        $stmt = $pdo->prepare("
            SELECT f.*, e.event_name 
            FROM pafe_feedback f 
            LEFT JOIN pafe_events e ON f.event_id = e.id 
            WHERE f.event_id = ? 
            ORDER BY f.created_at DESC
        ");
        $stmt->execute([$selected_event_id]);
        $feedbacks = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        $feedbacks = [];
        error_log("Error fetching feedback: " . $e->getMessage());
    }
}

// Check for messages
$success = isset($_GET['success']) ? $_GET['success'] : null;
$error = isset($_GET['error']) ? $_GET['error'] : null;

// Prepare calendar events
$calendar_events = [];
foreach ($events as $event) {
    if (
        !isset($event['id']) ||
        !isset($event['event_name']) ||
        !isset($event['event_date']) ||
        !isset($event['event_time']) ||
        !isset($event['status']) ||
        !isset($event['description']) ||
        !isset($event['created_at'])
    ) {
        error_log("Skipping event with missing fields: " . json_encode($event));
        continue;
    }
    $calendar_events[] = [
        'id' => $event['id'],
        'title' => $event['event_name'],
        'start' => $event['event_date'] . 'T' . $event['event_time'],
        'end' => date('Y-m-d\TH:i:s', strtotime($event['event_date'] . ' ' . $event['event_time'] . ' +2 hours')),
        'className' => 'fc-event-' . strtolower($event['status']),
        'extendedProps' => [
            'description' => $event['description'],
            'status' => $event['status'],
            'time' => $event['event_time'],
            'created_at' => $event['created_at']
        ]
    ];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prime Association of Future Educators</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://cdn.jsdelivr.net/npm/fullcalendar@5.11.0/main.min.css" rel="stylesheet">
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f4f4f4;
        }
        .sidebar {
            height: 100vh;
            position: fixed;
            top: 0;
            left: 0;
            width: 250px;
            background-color: #1a2b4e;
            padding-top: 20px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar.collapsed {
            width: 80px;
        }
        .sidebar.collapsed .sidebar-text {
            display: none;
        }
        .sidebar.collapsed .nav-link {
            text-align: center;
        }
        .sidebar.collapsed .sidebar-logo, .sidebar.collapsed .sidebar-divider {
            display: none;
        }
        .sidebar .nav-link {
            color: #ffffff;
            padding: 10px 15px;
            margin: 5px 10px;
            border-radius: 5px;
            display: flex;
            align-items: center;
        }
        .sidebar .nav-link:hover {
            background-color: #2e4372;
        }
        .sidebar .nav-link i {
            margin-right: 10px;
            font-size: 1.2rem;
        }
        .sidebar-logo {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-bottom: 20px;
        }
        .sidebar-logo img {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            margin-bottom: 10px;
        }
        .sidebar-logo h4 {
            color: #ffffff;
            font-size: 1.2rem;
            text-align: center;
            margin: 0;
        }
        .sidebar-divider {
            border-top: 1px solid #ffffff;
            margin: 10px 20px;
            opacity: 0.3;
        }
        .sidebar-menu-header {
            color: #ffffff;
            font-size: 0.9rem;
            margin: 10px 20px 5px;
            text-transform: uppercase;
            opacity: 0.7;
        }
        .content {
            margin-left: 250px;
            padding: 20px;
            transition: all 0.3s;
            margin-top: 80px;
        }
        .content.expanded {
            margin-left: 80px;
        }
        .header {
            background-color:rgb(245, 172, 1);
            padding: 10px 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            position: fixed;
            width: calc(100% - 250px);
            top: 0;
            left: 250px;
            z-index: 999;
            transition: all 0.3s;
        }
        .header.expanded {
            width: calc(100% - 80px);
            left: 80px;
        }
        .user-img {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            object-fit: cover;
            border: 2px solid #ffffff;
            box-shadow: 0 0 5px rgba(0,0,0,0.2);
        }
        .modal-body .user-img {
            width: 100px;
            height: 100px;
        }
        .logo-img {
            width: 40px;
            height: 40px;
            margin-right: 10px;
        }
        .toggle-btn {
            cursor: pointer;
            font-size: 20px;
        }
        .event-card, .stat-card, .attendance-card, .feedback-card, .report-card {
            background-color: #1a2b4e;
            color: #ffffff;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 15px;
            margin-bottom: 15px;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        .event-card:hover, .stat-card:hover, .attendance-card:hover, .feedback-card:hover, .report-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            background-color: #233a69;
        }
        .stat-card, .report-card {
            text-align: center;
        }
        .stat-card i, .report-card i {
            font-size: 2.5rem;
            margin-bottom: 15px;
        }
        .stat-card h3, .report-card h3 {
            margin: 10px 0;
            font-size: 2rem;
            font-weight: bold;
            color: rgb(255, 255, 255);
        }
        .stat-card p, .report-card p {
            margin: 0;
            font-size: 1.1rem;
            color: rgb(255, 255, 255);
            opacity: 0.9;
        }
        .status-scheduled { color:rgb(0, 123, 255); }
        .status-ongoing { color: #28a745; }
        .status-completed { color: #6c757d; }
        .status-canceled { color: #dc3545; }
        .status-decline { color: #dc3545; }
        .status-accepted { color: #28a745; }
        .status-rejected { color: #dc3545; }
        #calendar {
            max-width: 1100px;
            margin: 20px auto;
            background-color: #ffffff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .fc-event {
            cursor: pointer;
        }
        .fc-event-scheduled {
            background-color: #007bff;
            border-color: #007bff;
        }
        .fc-event-ongoing {
            background-color: #28a745;
            border-color: #28a745;
        }
        .fc-event-completed {
            background-color:rgb(163, 171, 179);
            border-color: #6c757d;
        }
        .fc-event-canceled {
            background-color: #dc3545;
            border-color: #dc3545;
        }
        #profile_picture {
            margin-top: 10px;
        }
        @media (max-width: 768px) {
            .sidebar {
                width: 80px;
            }
            .sidebar .sidebar-text, .sidebar-logo, .sidebar-divider, .sidebar-menu-header {
                display: none;
            }
            .sidebar .nav-link {
                text-align: center;
            }
            .content {
                margin-left: 80px;
            }
            .header {
                width: calc(100% - 80px);
                left: 80px;
            }
        }
        .stat-card {
            background-color: #1a2b4e;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
            text-align: center;
            color: #ffffff;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            background-color: #233a69;
        }
        .stat-card i {
            font-size: 2.5rem;
            margin-bottom: 15px;
        }
        .stat-card h3 {
            font-size: 2rem;
            margin: 10px 0;
            font-weight: bold;
        }
        .stat-card p {
            font-size: 1.1rem;
            margin: 0;
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header" id="header">
        <div class="d-flex justify-content-between align-items-center">
            <div class="d-flex align-items-center">
                <h4 class="mb-0">Prime Association of Future Educators</h4>
            </div>
            <div class="d-flex align-items-center">
                <?php
                // Fetch user profile information from user_profile table
                $stmt = $pdo->prepare("SELECT full_name, email, profile_picture FROM pafe_user_profile WHERE user_id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $user_profile = $stmt->fetch(PDO::FETCH_ASSOC);
                
                // Fallback values
                $full_name = $user_profile['full_name'] ?? $_SESSION['user_name'] ?? 'John Doe';
                $email = $user_profile['email'] ?? $_SESSION['email'] ?? '';
                $profile_picture = $user_profile['profile_picture'] ?? 'default.png';
                $profile_picture_path = htmlspecialchars('Uploads/profile_pictures/' . $profile_picture);
                ?>
                <img src="<?php echo $profile_picture_path; ?>" alt="User" class="user-img me-2" id="headerProfilePic">
                <div class="dropdown">
                    <a class="dropdown-toggle text-dark text-decoration-none" href="#" role="button" id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                        <?php echo htmlspecialchars($full_name); ?>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                        <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#manageProfileModal">Manage</a></li>
                        <li><a class="dropdown-item" href="logout.php">Log Out</a></li>
                    </ul>
                </div>
            </div>
        </div>
    </header>

    <!-- Manage Profile Modal -->
    <div class="modal fade" id="manageProfileModal" tabindex="-1" aria-labelledby="manageProfileModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="manageProfileModalLabel">Manage Profile</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="manageProfileForm" method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="update_profile">
                        <div class="mb-3">
                            <label for="profile_picture" class="form-label">Profile Picture</label>
                            <input type="file" class="form-control" id="profile_picture" name="profile_picture" accept="image/*">
                            <img id="profilePicturePreview" src="<?php echo $profile_picture_path; ?>" alt="Preview" class="img-fluid mt-2" style="max-width: 100px; max-height: 100px;">
                        </div>
                        <div class="mb-3">
                            <label for="full_name" class="form-label">Full Name</label>
                            <input type="text" class="form-control" id="full_name" name="full_name" value="<?php echo htmlspecialchars($full_name); ?>" required>
                        </div>
                        <div class="mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($email); ?>" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Sidebar -->
    <nav class="sidebar" id="sidebar">
        <div class="sidebar-logo">
            <img src="PAFE.jpg" alt="Logo">
            <h4>P  A  F  E</h4>
        </div>
        <div class="sidebar-divider"></div>
        <div class="d-flex justify-content-between align-items-center p-3">
            <h5 class="text-white sidebar-text mb-0">Menu</h5>
            <i class="fas fa-bars toggle-btn text-white" id="toggleBtn"></i>
        </div>
        <ul class="nav flex-column">
            <li class="nav-item">
                <a class="nav-link" href="?page=home"><i class="fas fa-home"></i><span class="sidebar-text">Home</span></a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="?page=events"><i class="fas fa-calendar-alt"></i><span class="sidebar-text">Events</span></a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="?page=attendance"><i class="fas fa-check-square"></i><span class="sidebar-text">Attendance</span></a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="?page=feedback"><i class="fas fa-comment-dots"></i><span class="sidebar-text">Feedback</span></a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="?page=reports"><i class="fas fa-file-alt"></i><span class="sidebar-text">Generate Report</span></a>
            </li>
        </ul>
    </nav>

    <!-- Main Content -->
    <div class="content" id="content">
        <?php
        $page = isset($_GET['page']) ? $_GET['page'] : 'home';
        ?>
        <?php if ($page === 'home'): ?>
            <h2>Welcome to the Prime Association of Future Educators</h2>
            <?php if (isset($success)): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            <?php if (isset($error)): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <div class="row">
                <div class="col-md-4">
                    <div class="stat-card">
                        <i class="fas fa-calendar-alt text-primary"></i>
                        <h3><?php echo htmlspecialchars($total_events); ?></h3>
                        <p>Total Events</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="stat-card">
                        <i class="fas fa-comment-dots text-success"></i>
                        <h3><?php echo htmlspecialchars($total_feedback); ?></h3>
                        <p>Total Feedback</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="stat-card">
                        <i class="fas fa-check-square text-info"></i>
                        <h3><?php echo htmlspecialchars($total_attendance); ?></h3>
                        <p>Total Attendance</p>
                    </div>
                </div>
            </div>
            <h3 class="mt-4">Event Calendar</h3>
            <div id="calendar"></div>
            <!-- Event Details Modals -->
            <?php foreach ($events as $event): ?>
                <?php if (!isset($event['id'])) continue; ?>
                <div class="modal fade" id="detailsEventModal<?php echo htmlspecialchars($event['id']); ?>" tabindex="-1" aria-labelledby="detailsEventModalLabel<?php echo htmlspecialchars($event['id']); ?>" aria-hidden="true">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title" id="detailsEventModalLabel<?php echo htmlspecialchars($event['id']); ?>">Event Details</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                <p><strong>Name:</strong> <?php echo htmlspecialchars($event['event_name'] ?? ''); ?></p>
                                <p><strong>Date:</strong> <?php echo htmlspecialchars($event['event_date'] ?? ''); ?></p>
                                <p><strong>Time:</strong> <?php echo htmlspecialchars($event['event_time'] ?? ''); ?></p>
                                <p><strong>Status:</strong> <span class="status-<?php echo strtolower($event['status'] ?? ''); ?>"><?php echo htmlspecialchars($event['status'] ?? ''); ?></span></p>
                                <p><strong>Description:</strong> <?php echo nl2br(htmlspecialchars($event['description'] ?? '')); ?></p>
                                <p><strong>Created At:</strong> <?php echo htmlspecialchars($event['created_at'] ?? ''); ?></p>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php elseif ($page === 'events'): ?>
            <h2>Manage Events</h2>
            <?php if (isset($success)): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            <?php if (isset($error)): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <button class="btn btn-primary mb-3" data-bs-toggle="modal" data-bs-target="#createEventModal">Create New Event</button>
            <div class="modal fade" id="createEventModal" tabindex="-1" aria-labelledby="createEventModalLabel" aria-hidden="true">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title" id="createEventModalLabel">Create Event</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <form method="POST" id="createEventForm">
                            <div class="modal-body">
                                <input type="hidden" name="action" value="create_event">
                                <div class="mb-3">
                                    <label for="event_name" class="form-label">Event Name</label>
                                    <input type="text" class="form-control" id="event_name" name="event_name" required>
                                </div>
                                <div class="mb-3">
                                    <label for="event_date" class="form-label">Date</label>
                                    <input type="date" class="form-control" id="event_date" name="event_date" required>
                                </div>
                                <div class="mb-3">
                                    <label for="event_time" class="form-label">Time</label>
                                    <input type="time" class="form-control" id="event_time" name="event_time" required>
                                </div>
                                <div class="mb-3">
                                    <label for="status" class="form-label">Status</label>
                                    <select class="form-select" id="status" name="status" required>
                                        <option value="Scheduled">Scheduled</option>
                                        <option value="Ongoing">Ongoing</option>
                                        <option value="Completed">Completed</option>
                                        <option value="Canceled">Canceled</option>
                                    </select>
                                </div>
                                <div class="mb-3">
                                    <label for="description" class="form-label">Description</label>
                                    <textarea class="form-control" id="description" name="description" rows="4"></textarea>
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                <button type="submit" class="btn btn-primary">Create Event</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            <div class="row">
                <?php foreach ($events as $event): ?>
                    <?php if (!isset($event['id'])) continue; ?>
                    <div class="col-md-6 col-lg-4" key="<?php echo htmlspecialchars($event['id']); ?>">
                        <div class="event-card" data-bs-toggle="modal" data-bs-target="#detailsEventModal<?php echo htmlspecialchars($event['id']); ?>">
                            <h5><?php echo htmlspecialchars($event['event_name'] ?? ''); ?></h5>
                            <p><strong>Date:</strong> <?php echo htmlspecialchars($event['event_date'] ?? ''); ?></p>
                            <p><strong>Time:</strong> <?php echo htmlspecialchars($event['event_time'] ?? ''); ?></p>
                            <p><strong>Status:</strong> <span class="status-<?php echo strtolower($event['status'] ?? ''); ?>"><?php echo htmlspecialchars($event['status'] ?? ''); ?></span></p>
                            <p><strong>Description:</strong> <?php echo nl2br(htmlspecialchars(substr($event['description'] ?? '', 0, 100) . (strlen($event['description'] ?? '') > 100 ? '...' : ''))); ?></p>
                            <div class="d-flex justify-content-between">
                                <button class="btn btn-info btn-sm action-btn" data-bs-toggle="modal" data-bs-target="#detailsEventModal<?php echo htmlspecialchars($event['id']); ?>">Details</button>
                                <button class="btn btn-warning btn-sm action-btn" data-bs-toggle="modal" data-bs-target="#editEventModal<?php echo htmlspecialchars($event['id']); ?>">Edit</button>
                                <button class="btn btn-danger btn-sm action-btn" data-bs-toggle="modal" data-bs-target="#deleteEventModal<?php echo htmlspecialchars($event['id']); ?>">Delete</button>
                            </div>
                        </div>
                    </div>
                    <div class="modal fade" id="detailsEventModal<?php echo htmlspecialchars($event['id']); ?>" tabindex="-1" aria-labelledby="detailsEventModalLabel<?php echo htmlspecialchars($event['id']); ?>" aria-hidden="true">
                        <div class="modal-dialog">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title" id="detailsEventModalLabel<?php echo htmlspecialchars($event['id']); ?>">Event Details</h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                </div>
                                <div class="modal-body">
                                    <p><strong>Name:</strong> <?php echo htmlspecialchars($event['event_name'] ?? ''); ?></p>
                                    <p><strong>Date:</strong> <?php echo htmlspecialchars($event['event_date'] ?? ''); ?></p>
                                    <p><strong>Time:</strong> <?php echo htmlspecialchars($event['event_time'] ?? ''); ?></p>
                                    <p><strong>Status:</strong> <span class="status-<?php echo strtolower($event['status'] ?? ''); ?>"><?php echo htmlspecialchars($event['status'] ?? ''); ?></span></p>
                                    <p><strong>Description:</strong> <?php echo nl2br(htmlspecialchars($event['description'] ?? '')); ?></p>
                                    <p><strong>Created At:</strong> <?php echo htmlspecialchars($event['created_at'] ?? ''); ?></p>
                                </div>
                                <div class="modal-footer">
                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal fade" id="editEventModal<?php echo htmlspecialchars($event['id']); ?>" tabindex="-1" aria-labelledby="editEventModalLabel<?php echo htmlspecialchars($event['id']); ?>" aria-hidden="true">
                        <div class="modal-dialog">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title" id="editEventModalLabel<?php echo htmlspecialchars($event['id']); ?>">Edit Event</h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                </div>
                                <form method="POST">
                                    <div class="modal-body">
                                        <input type="hidden" name="action" value="update_event">
                                        <input type="hidden" name="event_id" value="<?php echo htmlspecialchars($event['id']); ?>">
                                        <div class="mb-3">
                                            <label for="event_name_<?php echo htmlspecialchars($event['id']); ?>" class="form-label">Event Name</label>
                                            <input type="text" class="form-control" id="event_name_<?php echo htmlspecialchars($event['id']); ?>" name="event_name" value="<?php echo htmlspecialchars($event['event_name'] ?? ''); ?>" required>
                                        </div>
                                        <div class="mb-3">
                                            <label for="event_date_<?php echo htmlspecialchars($event['id']); ?>" class="form-label">Date</label>
                                            <input type="date" class="form-control" id="event_date_<?php echo htmlspecialchars($event['id']); ?>" name="event_date" value="<?php echo htmlspecialchars($event['event_date'] ?? ''); ?>" required>
                                        </div>
                                        <div class="mb-3">
                                            <label for="event_time_<?php echo htmlspecialchars($event['id']); ?>" class="form-label">Time</label>
                                            <input type="time" class="form-control" id="event_time_<?php echo htmlspecialchars($event['id']); ?>" name="event_time" value="<?php echo htmlspecialchars($event['event_time'] ?? ''); ?>" required>
                                        </div>
                                        <div class="mb-3">
                                            <label for="status_<?php echo htmlspecialchars($event['id']); ?>" class="form-label">Status</label>
                                            <select class="form-select" id="status_<?php echo htmlspecialchars($event['id']); ?>" name="status" required>
                                                <option value="Scheduled" <?php echo ($event['status'] ?? '') === 'Scheduled' ? 'selected' : ''; ?>>Scheduled</option>
                                                <option value="Ongoing" <?php echo ($event['status'] ?? '') === 'Ongoing' ? 'selected' : ''; ?>>Ongoing</option>
                                                <option value="Completed" <?php echo ($event['status'] ?? '') === 'Completed' ? 'selected' : ''; ?>>Completed</option>
                                                <option value="Canceled" <?php echo ($event['status'] ?? '') === 'Canceled' ? 'selected' : ''; ?>>Canceled</option>
                                            </select>
                                        </div>
                                        <div class="mb-3">
                                            <label for="description_<?php echo htmlspecialchars($event['id']); ?>" class="form-label">Description</label>
                                            <textarea class="form-control" id="description_<?php echo htmlspecialchars($event['id']); ?>" name="description" rows="4"><?php echo htmlspecialchars($event['description'] ?? ''); ?></textarea>
                                        </div>
                                    </div>
                                    <div class="modal-footer">
                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                        <button type="submit" class="btn btn-primary">Update Event</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                    <div class="modal fade" id="deleteEventModal<?php echo htmlspecialchars($event['id']); ?>" tabindex="-1" aria-labelledby="deleteEventModalLabel<?php echo htmlspecialchars($event['id']); ?>" aria-hidden="true">
                        <div class="modal-dialog">
                            <div class="modal-content">
                                <div class="modal-header">
                                    <h5 class="modal-title" id="deleteEventModalLabel<?php echo htmlspecialchars($event['id']); ?>">Delete Event</h5>
                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                </div>
                                <form method="POST">
                                    <div class="modal-body">
                                        <input type="hidden" name="action" value="delete_event">
                                        <input type="hidden" name="event_id" value="<?php echo htmlspecialchars($event['id']); ?>">
                                        <p>Are you sure you want to delete the event "<strong><?php echo htmlspecialchars($event['event_name'] ?? ''); ?></strong>"?</p>
                                    </div>
                                    <div class="modal-footer">
                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                        <button type="submit" class="btn btn-danger">Delete</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php elseif ($page === 'attendance'): ?>
            <h2>Manage Attendance</h2>
            <?php if (isset($success)): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            <?php if (isset($error)): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>

            <!-- Attendance Statistics -->
            <div class="row mb-4">
                <div class="col-md-4">
                    <div class="card bg-primary text-white">
                        <div class="card-body">
                            <h5 class="card-title">Total Attendance</h5>
                            <h2 class="card-text"><?php echo $total_count; ?></h2>
                            <p class="card-text">All attendance records</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card bg-warning text-white">
                        <div class="card-body">
                            <h5 class="card-title">Pending Approvals</h5>
                            <h2 class="card-text"><?php echo $pending_count; ?></h2>
                            <p class="card-text">Awaiting admin approval</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card bg-success text-white">
                        <div class="card-body">
                            <h5 class="card-title">Approved Attendance</h5>
                            <h2 class="card-text"><?php echo $approved_count; ?></h2>
                            <p class="card-text">Successfully approved records</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Filter Buttons -->
            <div class="mb-3">
                <div class="btn-group" role="group">
                    <button type="button" class="btn btn-outline-primary active" onclick="filterAttendance('all')">All</button>
                    <button type="button" class="btn btn-outline-warning" onclick="filterAttendance('pending')">Pending</button>
                    <button type="button" class="btn btn-outline-success" onclick="filterAttendance('approved')">Approved</button>
                    <button type="button" class="btn btn-outline-danger" onclick="filterAttendance('rejected')">Rejected</button>
                </div>
            </div>

            <!-- Attendance Table -->
            <div class="table-responsive">
                <table class="table table-striped table-hover" id="attendanceTable">
                    <thead>
                        <tr>
                            <th>Full Name</th>
                            <th>Event</th>
                            <th>Gender</th>
                            <th>Year Level</th>
                            <th>Section</th>
                            <th>Status</th>
                            <th>Created At</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($attendances)): ?>
                            <tr>
                                <td colspan="8" class="text-center">No attendance records found.</td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($attendances as $attendance): ?>
                                <?php if (!isset($attendance['id'])) continue; ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($attendance['fullname'] ?? ''); ?></td>
                                    <td><?php echo htmlspecialchars($attendance['event_name'] ?? 'No Event'); ?></td>
                                    <td><?php echo htmlspecialchars($attendance['gender'] ?? ''); ?></td>
                                    <td><?php echo htmlspecialchars($attendance['year_level'] ?? ''); ?></td>
                                    <td><?php echo htmlspecialchars($attendance['section'] ?? ''); ?></td>
                                    <td>
                                        <span class="badge <?php 
                                            switch(strtolower($attendance['status'] ?? '')) {
                                                case 'approved':
                                                    echo 'bg-success';
                                                    break;
                                                case 'pending':
                                                    echo 'bg-warning';
                                                    break;
                                                case 'rejected':
                                                    echo 'bg-danger';
                                                    break;
                                                default:
                                                    echo 'bg-secondary';
                                            }
                                        ?>">
                                            <?php echo htmlspecialchars($attendance['status'] ?? ''); ?>
                                        </span>
                                    </td>
                                    <td><?php echo htmlspecialchars($attendance['created_at'] ?? ''); ?></td>
                                    <td>
                                        <?php if (strtolower($attendance['status']) === 'pending'): ?>
                                            <div class="btn-group" role="group">
                                                <form method="POST" style="display:inline;">
                                                    <input type="hidden" name="action" value="approve_attendance">
                                                    <input type="hidden" name="attendance_id" value="<?php echo htmlspecialchars($attendance['id']); ?>">
                                                    <button type="submit" class="btn btn-success btn-sm" title="Approve">
                                                        <i class="fas fa-check"></i>
                                                    </button>
                                                </form>
                                                <form method="POST" style="display:inline;">
                                                    <input type="hidden" name="action" value="reject_attendance">
                                                    <input type="hidden" name="attendance_id" value="<?php echo htmlspecialchars($attendance['id']); ?>">
                                                    <button type="submit" class="btn btn-danger btn-sm" title="Reject">
                                                        <i class="fas fa-times"></i>
                                                    </button>
                                                </form>
                                            </div>
                                        <?php endif; ?>
                                        <button class="btn btn-info btn-sm" data-bs-toggle="modal" data-bs-target="#detailsAttendanceModal<?php echo htmlspecialchars($attendance['id']); ?>" title="View Details">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                        <button class="btn btn-warning btn-sm" data-bs-toggle="modal" data-bs-target="#editAttendanceModal<?php echo htmlspecialchars($attendance['id']); ?>" title="Edit">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                        <button class="btn btn-danger btn-sm" data-bs-toggle="modal" data-bs-target="#deleteAttendanceModal<?php echo htmlspecialchars($attendance['id']); ?>" title="Delete">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </td>
                                </tr>

                                <!-- Details Modal -->
                                <div class="modal fade" id="detailsAttendanceModal<?php echo htmlspecialchars($attendance['id']); ?>" tabindex="-1" aria-hidden="true">
                                    <div class="modal-dialog">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h5 class="modal-title">Attendance Details</h5>
                                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                            </div>
                                            <div class="modal-body">
                                                <p><strong>Full Name:</strong> <?php echo htmlspecialchars($attendance['fullname'] ?? ''); ?></p>
                                                <p><strong>Event:</strong> <?php echo htmlspecialchars($attendance['event_name'] ?? 'No Event'); ?></p>
                                                <p><strong>Gender:</strong> <?php echo htmlspecialchars($attendance['gender'] ?? ''); ?></p>
                                                <p><strong>Year Level:</strong> <?php echo htmlspecialchars($attendance['year_level'] ?? ''); ?></p>
                                                <p><strong>Section:</strong> <?php echo htmlspecialchars($attendance['section'] ?? ''); ?></p>
                                                <p><strong>Status:</strong> 
                                                    <span class="badge <?php 
                                                        switch(strtolower($attendance['status'] ?? '')) {
                                                            case 'approved':
                                                                echo 'bg-success';
                                                                break;
                                                            case 'pending':
                                                                echo 'bg-warning';
                                                                break;
                                                            case 'rejected':
                                                                echo 'bg-danger';
                                                                break;
                                                            default:
                                                                echo 'bg-secondary';
                                                        }
                                                    ?>">
                                                        <?php echo htmlspecialchars($attendance['status'] ?? ''); ?>
                                                    </span>
                                                </p>
                                                <p><strong>Created At:</strong> <?php echo htmlspecialchars($attendance['created_at'] ?? ''); ?></p>
                                            </div>
                                            <div class="modal-footer">
                                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <!-- Edit Modal -->
                                <div class="modal fade" id="editAttendanceModal<?php echo htmlspecialchars($attendance['id']); ?>" tabindex="-1" aria-hidden="true">
                                    <div class="modal-dialog">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h5 class="modal-title">Edit Attendance</h5>
                                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                            </div>
                                            <form method="POST">
                                                <div class="modal-body">
                                                    <input type="hidden" name="action" value="update_attendance">
                                                    <input type="hidden" name="attendance_id" value="<?php echo htmlspecialchars($attendance['id']); ?>">
                                                    
                                                    <div class="mb-3">
                                                        <label for="fullname_<?php echo htmlspecialchars($attendance['id']); ?>" class="form-label">Full Name</label>
                                                        <input type="text" class="form-control" id="fullname_<?php echo htmlspecialchars($attendance['id']); ?>" name="fullname" value="<?php echo htmlspecialchars($attendance['fullname'] ?? ''); ?>" required>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <label for="event_id_<?php echo htmlspecialchars($attendance['id']); ?>" class="form-label">Event</label>
                                                        <select class="form-select" id="event_id_<?php echo htmlspecialchars($attendance['id']); ?>" name="event_id" required>
                                                            <?php foreach ($events as $event): ?>
                                                                <option value="<?php echo htmlspecialchars($event['id']); ?>" <?php echo ($attendance['event_id'] == $event['id']) ? 'selected' : ''; ?>>
                                                                    <?php echo htmlspecialchars($event['event_name']); ?>
                                                                </option>
                                                            <?php endforeach; ?>
                                                        </select>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <label for="gender_<?php echo htmlspecialchars($attendance['id']); ?>" class="form-label">Gender</label>
                                                        <select class="form-select" id="gender_<?php echo htmlspecialchars($attendance['id']); ?>" name="gender" required>
                                                            <option value="Male" <?php echo ($attendance['gender'] == 'Male') ? 'selected' : ''; ?>>Male</option>
                                                            <option value="Female" <?php echo ($attendance['gender'] == 'Female') ? 'selected' : ''; ?>>Female</option>
                                                            <option value="Other" <?php echo ($attendance['gender'] == 'Other') ? 'selected' : ''; ?>>Other</option>
                                                        </select>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <label for="year_level_<?php echo htmlspecialchars($attendance['id']); ?>" class="form-label">Year Level</label>
                                                        <input type="text" class="form-control" id="year_level_<?php echo htmlspecialchars($attendance['id']); ?>" name="year_level" value="<?php echo htmlspecialchars($attendance['year_level'] ?? ''); ?>" required>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <label for="section_<?php echo htmlspecialchars($attendance['id']); ?>" class="form-label">Section</label>
                                                        <input type="text" class="form-control" id="section_<?php echo htmlspecialchars($attendance['id']); ?>" name="section" value="<?php echo htmlspecialchars($attendance['section'] ?? ''); ?>" required>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <label for="status_<?php echo htmlspecialchars($attendance['id']); ?>" class="form-label">Status</label>
                                                        <select class="form-select" id="status_<?php echo htmlspecialchars($attendance['id']); ?>" name="status" required>
                                                            <option value="Pending" <?php echo ($attendance['status'] == 'Pending') ? 'selected' : ''; ?>>Pending</option>
                                                            <option value="Approved" <?php echo ($attendance['status'] == 'Approved') ? 'selected' : ''; ?>>Approved</option>
                                                            <option value="Rejected" <?php echo ($attendance['status'] == 'Rejected') ? 'selected' : ''; ?>>Rejected</option>
                                                        </select>
                                                    </div>
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                                    <button type="submit" class="btn btn-primary">Update Attendance</button>
                                                </div>
                                            </form>
                                        </div>
                                    </div>
                                </div>

                                <!-- Delete Modal -->
                                <div class="modal fade" id="deleteAttendanceModal<?php echo htmlspecialchars($attendance['id']); ?>" tabindex="-1" aria-hidden="true">
                                    <div class="modal-dialog">
                                        <div class="modal-content">
                                            <div class="modal-header">
                                                <h5 class="modal-title">Delete Attendance</h5>
                                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                            </div>
                                            <form method="POST">
                                                <div class="modal-body">
                                                    <input type="hidden" name="action" value="delete_attendance">
                                                    <input type="hidden" name="attendance_id" value="<?php echo htmlspecialchars($attendance['id']); ?>">
                                                    <p>Are you sure you want to delete this attendance record?</p>
                                                    <p><strong>Full Name:</strong> <?php echo htmlspecialchars($attendance['fullname'] ?? ''); ?></p>
                                                    <p><strong>Event:</strong> <?php echo htmlspecialchars($attendance['event_name'] ?? 'No Event'); ?></p>
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                                    <button type="submit" class="btn btn-danger">Delete</button>
                                                </div>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        <?php elseif ($page === 'feedback'): ?>
            <h2>Feedback Records</h2>
            <?php if (isset($success)): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            <?php if (isset($error)): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <!-- Event Selection Dropdown -->
            <div class="mb-3">
                <form method="GET">
                    <input type="hidden" name="page" value="feedback">
                    <label for="event_id" class="form-label">Select Event</label>
                    <select class="form-select" id="event_id" name="event_id" onchange="this.form.submit()">
                        <option value="">Select an Event</option>
                        <?php foreach ($events as $event): ?>
                            <?php if (!isset($event['id'])) continue; ?>
                            <option value="<?php echo htmlspecialchars($event['id']); ?>" <?php echo $selected_event_id == $event['id'] ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($event['event_name'] ?? ''); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </form>
            </div>
            <!-- Feedback Cards -->
            <div class="row">
                <?php if ($selected_event_id && !empty($feedbacks)): ?>
                    <?php foreach ($feedbacks as $feedback): ?>
                        <?php if (!isset($feedback['id'])) continue; ?>
                        <div class="col-md-6 col-lg-4" key="<?php echo htmlspecialchars($feedback['id']); ?>">
                            <div class="feedback-card">
                                <h5><?php echo htmlspecialchars($feedback['event_name'] ?? ''); ?></h5>
                                <p><strong>User:</strong> <?php echo htmlspecialchars($feedback['user_name'] ?? ''); ?></p>
                                <p><strong>Comment:</strong> <?php echo nl2br(htmlspecialchars($feedback['comment'] ?? '')); ?></p>
                                <p><strong>Rating:</strong> <?php echo htmlspecialchars($feedback['rating'] ?? ''); ?>/5</p>
                                <p><strong>Created At:</strong> <?php echo htmlspecialchars($feedback['created_at'] ?? ''); ?></p>
                                <div class="mt-3">
                                    <button type="button" class="btn btn-danger btn-sm" data-bs-toggle="modal" data-bs-target="#deleteFeedbackModal<?php echo htmlspecialchars($feedback['id']); ?>">
                                        <i class="fas fa-trash"></i> Delete
                                    </button>
                                </div>
                            </div>
                        </div>
                        <!-- Delete Feedback Confirmation Modal -->
                        <div class="modal fade" id="deleteFeedbackModal<?php echo htmlspecialchars($feedback['id']); ?>" tabindex="-1" aria-labelledby="deleteFeedbackModalLabel<?php echo htmlspecialchars($feedback['id']); ?>" aria-hidden="true">
                            <div class="modal-dialog">
                                <div class="modal-content">
                                    <div class="modal-header">
                                        <h5 class="modal-title" id="deleteFeedbackModalLabel<?php echo htmlspecialchars($feedback['id']); ?>">Delete Feedback</h5>
                                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                    </div>
                                    <div class="modal-body">
                                        <p>Are you sure you want to delete this feedback from "<?php echo htmlspecialchars($feedback['user_name']); ?>" for event "<?php echo htmlspecialchars($feedback['event_name']); ?>"?</p>
                                        <p>This action cannot be undone.</p>
                                    </div>
                                    <div class="modal-footer">
                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                                        <form method="POST" style="display: inline;" class="delete-feedback-form">
                                            <input type="hidden" name="action" value="delete_feedback">
                                            <input type="hidden" name="feedback_id" value="<?php echo htmlspecialchars($feedback['id']); ?>">
                                            <button type="submit" class="btn btn-danger">Delete Feedback</button>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php elseif ($selected_event_id): ?>
                    <p>No feedback available for this event.</p>
                <?php else: ?>
                    <p>Please select an event to view feedback.</p>
                <?php endif; ?>
            </div>
        <?php elseif ($page === 'reports'): ?>
            <h2>Generate Reports</h2>
            <?php if (isset($success)): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            <?php if (isset($error)): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <div class="row">
                <div class="col-md-12">
                    <div class="report-card">
                        <i class="fas fa-file-alt text-primary"></i>
                        <h3>Generate Report</h3>
                        <p>Select the type of report you want to generate and download.</p>
                        <form method="POST">
                            <input type="hidden" name="action" value="generate_report">
                            <div class="mb-3">
                                <label for="report_type" class="form-label">Report Type</label>
                                <select class="form-select" id="report_type" name="report_type" required>
                                    <option value="">Select Report Type</option>
                                    <option value="events">Events</option>
                                    <option value="attendance">Attendance</option>
                                    <option value="feedback">Feedback</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-primary">Generate & Download CSV</button>
                        </form>
                    </div>
                </div>
            </div>
        <?php else: ?>
            <h2><?php echo ucfirst($page); ?></h2>
            <p>Content for <?php echo htmlspecialchars($page); ?> page goes here.</p>
        <?php endif; ?>
    </div>

     <!-- Manage Profile Modal -->
    <div class="modal fade" id="manageProfileModal" tabindex="-1" aria-labelledby="manageProfileModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="manageProfileModalLabel">Manage Profile</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="manageProfileForm" method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="update_profile">
                        <div class="mb-3">
                            <label for="profile_picture" class="form-label">Profile Picture</label>
                            <input type="file" class="form-control" id="profile_picture" name="profile_picture" accept="image/*">
                            <img id="profilePicturePreview" src="<?php echo $profile_picture_path; ?>" alt="Preview" class="img-fluid mt-2" style="max-width: 100px; max-height: 100px;">
                        </div>
                        <div class="mb-3">
                            <label for="full_name" class="form-label">Full Name</label>
                            <input type="text" class="form-control" id="full_name" name="full_name" value="<?php echo htmlspecialchars($full_name); ?>" required>
                        </div>
                        <div class="mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($email); ?>" required>
                        </div>
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/fullcalendar@5.11.0/main.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const toggleBtn = document.getElementById('toggleBtn');
            const sidebar = document.getElementById('sidebar');
            const content = document.getElementById('content');
            const header = document.getElementById('header');

            toggleBtn.addEventListener('click', () => {
                sidebar.classList.toggle('collapsed');
                content.classList.toggle('expanded');
                header.classList.toggle('expanded');
            });

            const createEventModal = document.getElementById('createEventModal');
            if (createEventModal) {
                createEventModal.addEventListener('hidden.bs.modal', () => {
                    document.getElementById('createEventForm').reset();
                });
            }

            const createAttendanceModal = document.getElementById('createAttendanceModal');
            if (createAttendanceModal) {
                createAttendanceModal.addEventListener('hidden.bs.modal', () => {
                    document.getElementById('createAttendanceForm').reset();
                });
            }

            const manageProfileModal = document.getElementById('manageProfileModal');
            if (manageProfileModal) {
                // Handle form submission
                const manageProfileForm = document.getElementById('manageProfileForm');
                manageProfileForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    
                    const formData = new FormData(this);
                    
                    fetch(window.location.href, {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => response.text())
                    .then(html => {
                        // Update the header username
                        const fullName = formData.get('full_name');
                        document.querySelector('#userDropdown').textContent = fullName;
                        
                        // Close the modal
                        const modal = bootstrap.Modal.getInstance(manageProfileModal);
                        modal.hide();
                        
                        // Show success message
                        const successAlert = document.createElement('div');
                        successAlert.className = 'alert alert-success alert-dismissible fade show';
                        successAlert.innerHTML = `
                            Profile updated successfully
                            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                        `;
                        document.querySelector('.content').insertBefore(successAlert, document.querySelector('.content').firstChild);
                        
                        // Remove success message after 3 seconds
                        setTimeout(() => {
                            successAlert.remove();
                        }, 3000);
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        // Show error message
                        const errorAlert = document.createElement('div');
                        errorAlert.className = 'alert alert-danger alert-dismissible fade show';
                        errorAlert.innerHTML = `
                            An error occurred while updating the profile
                            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                        `;
                        document.querySelector('.content').insertBefore(errorAlert, document.querySelector('.content').firstChild);
                    });
                });

                manageProfileModal.addEventListener('hidden.bs.modal', () => {
                    document.getElementById('manageProfileForm').reset();
                    // Reset profile picture preview to original
                    const headerImg = document.getElementById('headerProfilePic');
                    headerImg.src = '<?php echo htmlspecialchars($profile_picture_path); ?>';
                });
            }

            document.querySelectorAll('.action-btn').forEach(button => {
                button.addEventListener('click', (event) => {
                    event.stopPropagation();
                });
            });

            document.querySelectorAll('.attendance-card, .event-card').forEach(card => {
                card.addEventListener('click', (event) => {
                    if (!event.target.classList.contains('action-btn')) {
                        const modalId = card.getAttribute('data-bs-target');
                        const modal = document.querySelector(modalId);
                        if (modal) {
                            const bsModal = new bootstrap.Modal(modal);
                            bsModal.show();
                        }
                    }
                });
            });

            const calendarEl = document.getElementById('calendar');
            if (calendarEl) {
                console.log('Initializing FullCalendar...');
                const calendar = new FullCalendar.Calendar(calendarEl, {
                    initialView: 'dayGridMonth',
                    events: <?php echo json_encode($calendar_events); ?>,
                    eventClick: function(info) {
                        console.log('Event clicked:', info.event.id);
                        const modalId = `detailsEventModal${info.event.id}`;
                        const modal = document.getElementById(modalId);
                        if (modal) {
                            console.log('Showing modal:', modalId);
                            const bsModal = new bootstrap.Modal(modal);
                            bsModal.show();
                        } else {
                            console.error('Modal not found:', modalId);
                        }
                    },
                    height: 'auto',
                    headerToolbar: {
                        left: 'prev,next today',
                        center: 'title',
                        right: 'dayGridMonth,timeGridWeek,timeGridDay'
                    },
                    eventDidMount: function(info) {
                        console.log('Event rendered:', info.event.title, info.event.start);
                    }
                });
                try {
                    calendar.render();
                    console.log('Calendar rendered successfully.');
                } catch (error) {
                    console.error('Error rendering calendar:', error);
                }
            } else {
                console.error('Calendar element not found.');
            }

            // Add handler for feedback deletion
            document.querySelectorAll('.delete-feedback-form').forEach(form => {
                form.addEventListener('submit', function(e) {
                    e.preventDefault();
                    
                    const formData = new FormData(this);
                    const feedbackCard = this.closest('.col-md-6');
                    const modal = this.closest('.modal');
                    
                    fetch(window.location.href, {
                        method: 'POST',
                        body: formData,
                        headers: {
                            'X-Requested-With': 'XMLHttpRequest'
                        }
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            // Update the feedback count in the stats card
                            const feedbackCountElement = document.querySelector('.stat-card:nth-child(2) h3');
                            if (feedbackCountElement) {
                                feedbackCountElement.textContent = data.new_count;
                            }

                            // Close the modal
                            const bsModal = bootstrap.Modal.getInstance(modal);
                            bsModal.hide();

                            // Remove the feedback card
                            if (feedbackCard) {
                                feedbackCard.remove();
                            }

                            // Show success message
                            const successAlert = document.createElement('div');
                            successAlert.className = 'alert alert-success alert-dismissible fade show';
                            successAlert.innerHTML = `
                                ${data.message}
                                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                            `;
                            document.querySelector('.content').insertBefore(successAlert, document.querySelector('.content').firstChild);

                            // Remove success message after 3 seconds
                            setTimeout(() => {
                                successAlert.remove();
                            }, 3000);
                        } else {
                            throw new Error(data.error || 'An error occurred');
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        // Show error message
                        const errorAlert = document.createElement('div');
                        errorAlert.className = 'alert alert-danger alert-dismissible fade show';
                        errorAlert.innerHTML = `
                            ${error.message}
                            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                        `;
                        document.querySelector('.content').insertBefore(errorAlert, document.querySelector('.content').firstChild);
                    });
                });
            });
        });

        function filterAttendance(status) {
            const table = document.getElementById('attendanceTable');
            const rows = table.getElementsByTagName('tr');
            
            // Update active button
            document.querySelectorAll('.btn-group .btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Show/hide rows based on status
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const statusCell = row.querySelector('td:nth-child(6)');
                
                if (status === 'all') {
                    row.style.display = '';
                } else {
                    const rowStatus = statusCell.textContent.trim().toLowerCase();
                    row.style.display = rowStatus === status ? '' : 'none';
                }
            }
        }

        // Add animation to statistics cards
        document.addEventListener('DOMContentLoaded', function() {
            const cards = document.querySelectorAll('.card');
            cards.forEach(card => {
                card.style.transition = 'transform 0.3s ease';
                card.addEventListener('mouseover', function() {
                    this.style.transform = 'scale(1.05)';
                });
                card.addEventListener('mouseout', function() {
                    this.style.transform = 'scale(1)';
                });
            });
        });

        function previewImage(input) {
            if (input.files && input.files[0]) {
                const reader = new FileReader();
                
                reader.onload = function(e) {
                    // Update both the modal preview and header image
                    document.getElementById('profilePreview').src = e.target.result;
                    document.getElementById('headerProfilePic').src = e.target.result;
                }
                
                reader.readAsDataURL(input.files[0]);
            }
        }
    </script>
</body>
</html>