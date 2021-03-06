﻿using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityService.Models
{
    public class ApplicationUser : IdentityUser
    {
        [MaxLength(36)]
        public override string Id { get => base.Id; set => base.Id = value; }

        public ApplicationUser()
        {
            Id = Nanoid.Nanoid.Generate(size: 36);
        }
    }
}
