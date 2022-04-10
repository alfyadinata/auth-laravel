<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Input;
use Auth;
use App\Models\User;

class AuthController extends Controller
{
    public function response($user)
    {
        $token  =   $user->createToken( str()->random(40) )->plainTextToken;

        return response()->json([
            'user'          =>  $user,
            'token'         =>  $token,
            'token_type'    =>  'Bearer'
        ]);
    }

    public function register(Request $request)
    {
        $request->validate([
            'name'          =>  'required|min:3',
            'email'         =>  'required|unique:users',
            'password'      =>  'required|min:6',
        ]);
        
        try {
            $user   =   User::create([
                'name'      =>  $request->name,
                'email'     =>  $request->email,
                'password'  =>  bcrypt($request->password)
            ]);
    
            return $this->response($user);
        } catch (\Exception $th) {
            return response()->json([
                'message'   =>  $th->getMessage()
            ],500);
        }

    }

    public function login(Request $request)
    {
        try {
            $request->validate([
                'email'         =>  'required|email|exists:users',
                'password'      =>  'required|min:6',
            ]);

            if (!Auth::attempt($request->only(['email','password']))) {
                return response()->json([
                    'message'   =>  'Unauthorized'
                ],401);
            }
    
            return $this->response(Auth::user());
        } catch (\Exception $th) {
            return response()->json([
                'message'   =>  $th->getMessage()
            ],500);
        }

    }

    public function logout()
    {
        try {
            Auth::user()->tokens()->delete();
    
            return response()->json([
                'message'   =>  'You have successfully logged out.'
            ]);
        } catch (\Exception $th) {
            return response()->json([
                'message'   =>  $th->getMessage()
            ],500);
        }
    }

    public function show()
    {
        try {
            return response()->json(Auth::user());
        } catch (\Exception $th) {
            return response()->json([
                'message'   =>  $th->getMessage()
            ],500);
        }
    }

    public function update(Request $request)
    {
        $request->validate([
            'name'  =>  'required|min:3',
            'phone' =>  'required|min:6',
        ]);

        try {
            $user   =   User::findOrFail(Auth::user()->id);
            $user->update([
                'name'      =>  $request->name,
                'email'     =>  $request->email || $user->email,
                'password'  =>  $request->password ? bcrypt($request->password) : $user->password,
                'phone'     =>  $request->phone
            ]);

            return response()->json($user);
        } catch (\Throwable $th) {
            return response()->json([
                'message'   =>  $th
            ]);
        }
    }
}
