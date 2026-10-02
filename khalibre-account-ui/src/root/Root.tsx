import { AccountEnvironment, useEnvironment, usePromise, } from "@keycloak/keycloak-account-ui";
import { ErrorPage } from "@keycloak/keycloak-ui-shared";
import { Page, Spinner } from "@patternfly/react-core";
import { Suspense, useState } from "react";
import { createBrowserRouter, Outlet, RouteObject, RouterProvider, } from "react-router-dom";
import fetchContentJson from "../content/fetchContent";
import { environment } from "../environment";
import { routes } from "../routes";
import { Header } from "./Header";
import { MenuItem, PageNav } from "./PageNav.tsx";
import styles from "./Root.module.css";

function mapRoutes(content: MenuItem[]): RouteObject[] {
  return content
  .map((item) => {
    if ("children" in item) {
      return mapRoutes(item.children);
    }
    return {
      ...item,
      element:
        "path" in item
          ? routes.find((r) => r.path === (item.id ?? item.path))?.element
          : undefined,
    };
  })
  .flat();
}

export const Root = () => {
  const context = useEnvironment<AccountEnvironment>();
  const [content, setContent] = useState<RouteObject[]>();

  usePromise(
    (signal) => fetchContentJson({signal, context}),
    (content) => {
      setContent([
        {
          path: decodeURIComponent(new URL(environment.baseUrl).pathname),
          element: (
            <Page header={<Header/>} sidebar={<PageNav/>} isManagedSidebar
                  className={styles.accountConsolePage}>
              <Suspense fallback={<Spinner/>}>
                <Outlet/>
              </Suspense>
            </Page>
          ),
          errorElement: <ErrorPage/>,
          children: mapRoutes(content),
        },
      ]);
    },
  );

  if (!content) {
    return <Spinner/>;
  }
  return <RouterProvider router={createBrowserRouter(content)}/>;
};