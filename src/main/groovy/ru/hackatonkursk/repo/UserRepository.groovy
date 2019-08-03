package ru.hackatonkursk.repo


import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Service
import ru.hackatonkursk.domain.User

@Service
class UserRepository {

    private USERS = [
            new User('admin@mail.loc', '{noop}adminadmin',
                    [new SimpleGrantedAuthority('ROLE_ADMIN'),
                     new SimpleGrantedAuthority('ROLE_GUEST')]),
            new User('guest@mail.loc', '{noop}qwerty',
                    [new SimpleGrantedAuthority('ROLE_GUEST')])
    ]

    def findByEmail(String email) {
        return USERS.find { u -> u.username == email }
    }
}
