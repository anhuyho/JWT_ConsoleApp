﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JWT_ConsoleApp.Model
{
    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
    public class UserDto
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}