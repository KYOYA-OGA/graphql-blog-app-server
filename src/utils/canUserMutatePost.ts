import { Context } from '..';

interface canUserMutatePostParams {
  userId: number;
  postId: number;
  prisma: Context['prisma'];
}

export const canUserMutatePost = async ({
  userId,
  postId,
  prisma,
}: canUserMutatePostParams) => {
  const user = await prisma.user.findUnique({
    where: {
      id: userId,
    },
  });

  if (!user) {
    return {
      userErrors: [
        {
          message: 'User does not exist',
        },
      ],
      post: null,
    };
  }

  const post = await prisma.post.findUnique({
    where: {
      id: postId,
    },
  });

  if (post?.authorId !== user.id) {
    return {
      userErrors: [
        {
          message: 'User is not the author of the post',
        },
      ],
      post: null,
    };
  }
};
