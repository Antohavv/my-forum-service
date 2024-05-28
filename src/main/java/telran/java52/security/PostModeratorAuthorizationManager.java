package telran.java52.security;

import java.util.function.Supplier;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java52.accounting.dao.UserAccountRepository;
import telran.java52.accounting.model.Role;
import telran.java52.accounting.model.UserAccount;
import telran.java52.post.dao.PostRepository;
import telran.java52.post.dto.exceptions.PostNotFoundException;
import telran.java52.post.model.Post;

@Component
@RequiredArgsConstructor

public class PostModeratorAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
	final PostRepository postRepository;
	final UserAccountRepository userAccountRepository;

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
		String username = authentication.get().getName();
		String postId = context.getVariables().get("id");

		UserAccount user = userAccountRepository.findById(username).get();
		Post post = postRepository.findById(postId).orElseThrow(PostNotFoundException::new);

		boolean isAccsess = user.getRoles().contains(Role.MODERATOR) || post.getAuthor().equals(username);

		return new AuthorizationDecision(isAccsess);
	}

}
