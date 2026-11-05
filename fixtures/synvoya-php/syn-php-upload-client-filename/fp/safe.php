<?php
$ext = strtolower(pathinfo($_FILES['avatar']['name'], PATHINFO_EXTENSION));
if (in_array($ext, ['jpg', 'png', 'gif'], true)) {
    move_uploaded_file($_FILES['avatar']['tmp_name'], __DIR__ . '/uploads/' . bin2hex(random_bytes(8)) . '.' . $ext);
}
$name = md5($_FILES['doc']['name']) . '.pdf';
move_uploaded_file($_FILES['doc']['tmp_name'], 'docs/' . $name);
class AvatarController {
    public function store(Request $request) {
        $file = $request->file('avatar');
        $file->move(public_path('avatars'), $file->hashName());
        $file->storeAs('avatars', $file->getClientOriginalName());
    }
}
