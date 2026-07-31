res.cookie("session", token, { secure: true, httpOnly: true, sameSite: "strict" });
