<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;

class AuthController extends Controller
{
    /**
     * Registrasi pengguna baru
     */
    public function register(Request $request)
    {
        $validatedData = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
        ]);

        try {
            $user = User::create([
                'name' => $validatedData['name'],
                'email' => $validatedData['email'],
                'password' => bcrypt($validatedData['password']),
            ]);

            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'access_token' => $token,
                'token_type' => 'Bearer',
            ], 201); // Gunakan status code 201 untuk Created
        } catch (\Exception $e) {
            Log::error('Registrasi gagal: ' . $e->getMessage());
            return response()->json(['error' => 'Registrasi gagal, silakan coba lagi.'], 500);
        }
    }

    /**
     * Login pengguna
     */
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        // Cek kredensial login
        if (!Auth::attempt($credentials)) {
            return response()->json([
                'message' => 'Invalid login details'
            ], 401);
        }

        try {
            $user = User::where('email', $request->email)->firstOrFail();
            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'access_token' => $token,
                'token_type' => 'Bearer',
            ]);
        } catch (\Exception $e) {
            Log::error('Login gagal: ' . $e->getMessage());
            return response()->json(['error' => 'Login gagal, silakan coba lagi.'], 500);
        }
    }
}
