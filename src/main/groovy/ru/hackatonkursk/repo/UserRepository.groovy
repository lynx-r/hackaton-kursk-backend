package ru.hackatonkursk.repo


import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Service
import ru.hackatonkursk.domain.User

@Service
class UserRepository {

    private USERS = [
            new User('9999999999', 'password',
                    [new SimpleGrantedAuthority('ROLE_ADMIN'),
                     new SimpleGrantedAuthority('ROLE_GUEST')]),
            new User('9234567891', '{noop}guestguest',
                    [new SimpleGrantedAuthority('ROLE_GUEST')])
    ]

    def findByEmail(String email) {
        return USERS.find { u -> u.username == email }
    }
}
